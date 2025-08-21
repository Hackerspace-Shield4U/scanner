#!/usr/bin/env python3
"""
Template Manager for Shield4U Scanner
Manages Nuclei templates and custom templates
"""

import os
import logging
import json
import yaml
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path

from config import Config
from utils.logger import setup_logger

logger = setup_logger(__name__)

class TemplateManager:
    """Manages Nuclei templates"""
    
    def __init__(self):
        self.config = Config
        self.templates_path = Path(self.config.NUCLEI_TEMPLATES_PATH)
        self.custom_templates_path = Path(self.config.CUSTOM_TEMPLATES_PATH)
        
        # Create custom templates directory if it doesn't exist
        self.custom_templates_path.mkdir(parents=True, exist_ok=True)
    
    def get_template_count(self) -> int:
        """Get total number of available templates"""
        try:
            count = 0
            
            # Count official templates
            if self.templates_path.exists():
                for root, dirs, files in os.walk(self.templates_path):
                    count += len([f for f in files if f.endswith('.yaml') or f.endswith('.yml')])
            
            # Count custom templates
            if self.custom_templates_path.exists():
                for root, dirs, files in os.walk(self.custom_templates_path):
                    count += len([f for f in files if f.endswith('.yaml') or f.endswith('.yml')])
            
            return count
            
        except Exception as e:
            logger.error(f"Error counting templates: {str(e)}")
            return 0
    
    def list_available_templates(self) -> List[Dict[str, Any]]:
        """List all available templates with metadata"""
        templates = []
        
        try:
            # List official templates
            templates.extend(self._scan_templates_directory(self.templates_path, 'official'))
            
            # List custom templates
            if self.config.ENABLE_CUSTOM_TEMPLATES:
                templates.extend(self._scan_templates_directory(self.custom_templates_path, 'custom'))
            
            return templates
            
        except Exception as e:
            logger.error(f"Error listing templates: {str(e)}")
            return []
    
    def get_template_categories(self) -> Dict[str, List[str]]:
        """Get template categories and their templates"""
        categories = {}
        
        try:
            # Scan categories in templates directory
            if self.templates_path.exists():
                for item in self.templates_path.iterdir():
                    if item.is_dir():
                        category_name = item.name
                        template_files = []
                        
                        # Get template files in this category
                        for template_file in item.glob('*.y*ml'):
                            template_files.append(template_file.name)
                        
                        if template_files:
                            categories[category_name] = template_files
            
            return categories
            
        except Exception as e:
            logger.error(f"Error getting template categories: {str(e)}")
            return {}
    
    def create_custom_template(self, template_id: str, template_data: Dict[str, Any]) -> bool:
        """Create a custom template"""
        try:
            if not self.config.ENABLE_CUSTOM_TEMPLATES:
                raise Exception("Custom templates are disabled")
            
            # Validate template data
            if not self._validate_template_data(template_data):
                raise Exception("Invalid template data")
            
            # Create template file
            template_file = self.custom_templates_path / f"{template_id}.yaml"
            
            with open(template_file, 'w', encoding='utf-8') as f:
                yaml.dump(template_data, f, default_flow_style=False)
            
            logger.info(f"Created custom template: {template_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error creating custom template: {str(e)}")
            return False
    
    def delete_custom_template(self, template_id: str) -> bool:
        """Delete a custom template"""
        try:
            template_file = self.custom_templates_path / f"{template_id}.yaml"
            
            if template_file.exists():
                template_file.unlink()
                logger.info(f"Deleted custom template: {template_id}")
                return True
            else:
                logger.warning(f"Custom template not found: {template_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting custom template: {str(e)}")
            return False
    
    def update_templates(self) -> bool:
        """Update official templates"""
        try:
            logger.info("Updating Nuclei templates...")
            
            result = subprocess.run([
                self.config.NUCLEI_BINARY_PATH,
                '-update-templates',
                '-templates-directory',
                str(self.templates_path)
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logger.info("Templates updated successfully")
                return True
            else:
                logger.error(f"Template update failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating templates: {str(e)}")
            return False
    
    def get_template_info(self, template_path: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific template"""
        try:
            template_file = Path(template_path)
            
            if not template_file.exists():
                return None
            
            with open(template_file, 'r', encoding='utf-8') as f:
                template_data = yaml.safe_load(f)
            
            # Extract template metadata
            info = template_data.get('info', {})
            
            template_info = {
                'id': template_data.get('id', template_file.stem),
                'name': info.get('name', 'Unknown'),
                'author': info.get('author', []),
                'severity': info.get('severity', 'info'),
                'description': info.get('description', ''),
                'reference': info.get('reference', []),
                'tags': info.get('tags', []),
                'classification': info.get('classification', {}),
                'file_path': str(template_file),
                'file_size': template_file.stat().st_size
            }
            
            return template_info
            
        except Exception as e:
            logger.error(f"Error getting template info: {str(e)}")
            return None
    
    def search_templates(self, query: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search templates by name, tags, or description"""
        matching_templates = []
        
        try:
            templates = self.list_available_templates()
            
            for template in templates:
                # Category filter
                if category and template.get('category') != category:
                    continue
                
                # Text search in name, description, and tags
                search_text = ' '.join([
                    template.get('name', '').lower(),
                    template.get('description', '').lower(),
                    ' '.join(template.get('tags', [])).lower()
                ])
                
                if query.lower() in search_text:
                    matching_templates.append(template)
            
            return matching_templates
            
        except Exception as e:
            logger.error(f"Error searching templates: {str(e)}")
            return []
    
    def get_templates_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get templates filtered by severity"""
        try:
            templates = self.list_available_templates()
            return [t for t in templates if t.get('severity', '').lower() == severity.lower()]
            
        except Exception as e:
            logger.error(f"Error filtering templates by severity: {str(e)}")
            return []
    
    def _scan_templates_directory(self, directory: Path, template_type: str) -> List[Dict[str, Any]]:
        """Scan a directory for template files"""
        templates = []
        
        try:
            if not directory.exists():
                return templates
            
            for root, dirs, files in os.walk(directory):
                root_path = Path(root)
                
                for file in files:
                    if file.endswith('.yaml') or file.endswith('.yml'):
                        template_file = root_path / file
                        
                        try:
                            template_info = self.get_template_info(template_file)
                            if template_info:
                                template_info['type'] = template_type
                                template_info['category'] = root_path.relative_to(directory).parts[0] if root_path != directory else 'misc'
                                templates.append(template_info)
                                
                        except Exception as e:
                            logger.warning(f"Failed to parse template {template_file}: {str(e)}")
            
            return templates
            
        except Exception as e:
            logger.error(f"Error scanning templates directory: {str(e)}")
            return []
    
    def _validate_template_data(self, template_data: Dict[str, Any]) -> bool:
        """Validate template data structure"""
        try:
            # Basic structure validation
            required_fields = ['id', 'info', 'requests']
            
            for field in required_fields:
                if field not in template_data:
                    return False
            
            # Validate info section
            info = template_data.get('info', {})
            if not isinstance(info, dict):
                return False
            
            # Validate requests section
            requests = template_data.get('requests', [])
            if not isinstance(requests, list) or not requests:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating template data: {str(e)}")
            return False