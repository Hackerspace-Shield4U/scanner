#!/usr/bin/env python3
"""
Shield4U Scanner Service
Nuclei-based vulnerability scanner
"""

import os
import logging
import json
import subprocess
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Any

from flask import Flask, request, jsonify
import requests

from config import Config
from services.nuclei_scanner import NucleiScanner
from services.template_manager import TemplateManager
from utils.logger import setup_logger

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize services
nuclei_scanner = NucleiScanner()
template_manager = TemplateManager()

# Setup logging
logger = setup_logger(__name__, Config.LOG_FILE)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check Nuclei installation
        nuclei_version = nuclei_scanner.get_nuclei_version()
        
        # Check template availability
        template_count = template_manager.get_template_count()
        
        return jsonify({
            'status': 'healthy',
            'service': 'scanner',
            'timestamp': datetime.utcnow().isoformat(),
            'nuclei_version': nuclei_version,
            'template_count': template_count
        }), 200
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'service': 'scanner',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }), 500

@app.route('/scan', methods=['POST'])
def run_vulnerability_scan():
    """
    Run vulnerability scan based on analysis results
    
    Request body:
    {
        "task_guid": "uuid-string",
        "parent_guid": "uuid-string", 
        "analysis_result": {
            "id": 123,
            "crawl_result": {...},
            "scan_rules": {...}
        }
    }
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['task_guid', 'parent_guid', 'analysis_result']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'error': f'Missing required field: {field}',
                    'status': 'error'
                }), 400
        
        task_guid = data['task_guid']
        parent_guid = data['parent_guid']
        analysis_result = data['analysis_result']
        
        logger.info(f"Starting vulnerability scan task {task_guid}")
        
        # Extract scan parameters
        target_url = analysis_result.get('crawl_result', {}).get('url', '')
        scan_rules = analysis_result.get('scan_rules', {})
        
        if not target_url:
            raise Exception("No target URL found in analysis result")
        
        if not scan_rules:
            logger.info(f"No scan rules provided for {target_url}, running basic scan")
        
        # Perform vulnerability scan
        scan_results = nuclei_scanner.run_scan(
            target_url=target_url,
            scan_rules=scan_rules,
            analysis_id=analysis_result.get('id')
        )
        
        # Store scan results in database via controller
        scan_data = {
            'parent_guid': parent_guid,
            'analysis_id': analysis_result.get('id'),
            'target_url': target_url,
            'scan_results': scan_results
        }
        
        success = _store_scan_results(parent_guid, scan_data)
        
        if not success:
            raise Exception("Failed to store scan results")
        
        # Prepare result data
        result_data = {
            'analysis_id': analysis_result.get('id'),
            'target_url': target_url,
            'scan_results': scan_results,
            'scan_metadata': {
                'scan_time': datetime.utcnow().isoformat(),
                'templates_used': len(scan_rules.get('yaml_templates', '').split('---')) if scan_rules and scan_rules.get('yaml_templates') else 0,
                'vulnerabilities_found': len(scan_results)
            }
        }
        
        # Update task status and continue workflow
        _update_task_status(parent_guid, task_guid, 'completed', 'Scan completed successfully')
        
        logger.info(f"Scan task {task_guid} completed: {len(scan_results)} vulnerabilities found")
        
        return jsonify({
            'status': 'success',
            'task_guid': task_guid,
            'vulnerabilities_found': len(scan_results),
            'result': result_data
        }), 200
        
    except Exception as e:
        logger.error(f"Error in run_vulnerability_scan: {str(e)}")
        
        # Report failure to controller
        if 'task_guid' in locals() and 'parent_guid' in locals():
            _update_task_status(parent_guid, task_guid, 'failed', str(e))
        
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/scan/custom', methods=['POST'])
def run_custom_scan():
    """
    Run custom vulnerability scan with specific templates
    
    Request body:
    {
        "target_url": "https://example.com",
        "templates": ["xss", "sqli", "lfi"],
        "custom_templates": [{"id": "custom1", "template": "..."}]
    }
    """
    try:
        data = request.get_json()
        
        if 'target_url' not in data:
            return jsonify({
                'error': 'Missing required field: target_url',
                'status': 'error'
            }), 400
        
        target_url = data['target_url']
        templates = data.get('templates', [])
        custom_templates = data.get('custom_templates', [])
        
        logger.info(f"Running custom scan on {target_url}")
        
        # Run scan with specified templates
        scan_results = nuclei_scanner.run_custom_scan(
            target_url=target_url,
            template_list=templates,
            custom_templates=custom_templates
        )
        
        return jsonify({
            'status': 'success',
            'target_url': target_url,
            'vulnerabilities_found': len(scan_results),
            'results': scan_results
        }), 200
        
    except Exception as e:
        logger.error(f"Error in run_custom_scan: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/templates', methods=['GET'])
def list_templates():
    """List available Nuclei templates"""
    try:
        templates = template_manager.list_available_templates()
        
        return jsonify({
            'status': 'success',
            'template_count': len(templates),
            'templates': templates
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing templates: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/templates/categories', methods=['GET'])
def list_template_categories():
    """List template categories"""
    try:
        categories = template_manager.get_template_categories()
        
        return jsonify({
            'status': 'success',
            'categories': categories
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing template categories: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/validate', methods=['POST'])
def validate_target():
    """
    Validate target URL before scanning
    
    Request body:
    {
        "target_url": "https://example.com"
    }
    """
    try:
        data = request.get_json()
        
        if 'target_url' not in data:
            return jsonify({
                'error': 'Missing required field: target_url',
                'status': 'error'
            }), 400
        
        target_url = data['target_url']
        
        # Validate target
        is_valid, validation_result = nuclei_scanner.validate_target(target_url)
        
        return jsonify({
            'status': 'success',
            'target_url': target_url,
            'is_valid': is_valid,
            'validation_result': validation_result
        }), 200
        
    except Exception as e:
        logger.error(f"Error validating target: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

def _store_scan_results(parent_guid: str, scan_data: Dict[str, Any]) -> bool:
    """Store scan results in database via controller"""
    try:
        response = requests.post(
            f"{Config.CONTROLLER_URL}/internal/scan_results/store",
            json=scan_data,
            timeout=Config.SERVICE_REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            logger.info(f"Successfully stored scan results for {parent_guid}")
            return True
        else:
            logger.error(f"Failed to store scan results: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Error storing scan results: {str(e)}")
        return False

def _update_task_status(parent_guid: str, task_guid: str, status: str, message: str = ""):
    """Update task status via controller"""
    try:
        payload = {
            'task_guid': task_guid,
            'parent_guid': parent_guid,
            'service_name': 'scanner',
            'status': status,
            'message': message
        }
        
        response = requests.post(
            f"{Config.CONTROLLER_URL}/api/v1/internal/task_progress/update",
            json=payload,
            timeout=10
        )
        
        if response.status_code != 200:
            logger.warning(f"Failed to update task status: HTTP {response.status_code}")
            
    except Exception as e:
        logger.error(f"Error updating task status: {str(e)}")

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'status': 'error'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        'error': 'Internal server error',
        'status': 'error'
    }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)