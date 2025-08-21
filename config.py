#!/usr/bin/env python3
"""
Configuration settings for Shield4U Scanner
"""

import os

class Config:
    """Configuration class for Scanner service"""
    
    # Service configuration
    CONTROLLER_URL = os.environ.get('CONTROLLER_URL', 'http://localhost:5000')
    
    # Nuclei configuration
    NUCLEI_TEMPLATES_PATH = os.environ.get('NUCLEI_TEMPLATES_PATH', '/app/nuclei-templates')
    CUSTOM_TEMPLATES_PATH = os.environ.get('CUSTOM_TEMPLATES_PATH', '/app/custom-templates')
    NUCLEI_BINARY_PATH = os.environ.get('NUCLEI_BINARY_PATH', '/usr/local/bin/nuclei')
    
    # Scan settings
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', '600'))  # 10 minutes
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', '3'))
    SCAN_RATE_LIMIT = int(os.environ.get('SCAN_RATE_LIMIT', '100'))  # requests per second
    
    # Request settings
    SERVICE_REQUEST_TIMEOUT = int(os.environ.get('SERVICE_REQUEST_TIMEOUT', '30'))
    
    # Security settings
    USER_AGENT = 'Shield4U-Scanner/1.0 (Security Assessment Tool)'
    MAX_REDIRECTS = int(os.environ.get('MAX_REDIRECTS', '10'))
    
    # Template settings
    TEMPLATE_UPDATE_INTERVAL = int(os.environ.get('TEMPLATE_UPDATE_INTERVAL', '86400'))  # 24 hours
    ENABLE_CUSTOM_TEMPLATES = os.environ.get('ENABLE_CUSTOM_TEMPLATES', 'true').lower() == 'true'
    
    # Output settings
    OUTPUT_FORMAT = os.environ.get('OUTPUT_FORMAT', 'json')
    INCLUDE_RAW_OUTPUT = os.environ.get('INCLUDE_RAW_OUTPUT', 'false').lower() == 'true'
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', '/app/logs/scanner.log')
    
    # Nuclei options
    NUCLEI_CONFIG = {
        'concurrency': int(os.environ.get('NUCLEI_CONCURRENCY', '25')),
        'retries': int(os.environ.get('NUCLEI_RETRIES', '1')),
        'timeout': int(os.environ.get('NUCLEI_TIMEOUT', '5')),
        'bulk_size': int(os.environ.get('NUCLEI_BULK_SIZE', '25')),
        'rate_limit': SCAN_RATE_LIMIT,
        'no_color': True,
        'json': True,
        'silent': True
    }
    
    # Severity filtering
    MIN_SEVERITY = os.environ.get('MIN_SEVERITY', 'info')  # info, low, medium, high, critical
    SEVERITY_LEVELS = {
        'info': 0,
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }
    
    # Template categories
    DEFAULT_TEMPLATE_CATEGORIES = [
        'cves',
        'exposures',
        'misconfiguration',
        'technologies',
        'takeovers',
        'vulnerabilities',
        'workflows',
        'default-logins',
        'file',
        'dns',
        'headless'
    ]