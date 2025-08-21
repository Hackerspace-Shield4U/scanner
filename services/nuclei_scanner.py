#!/usr/bin/env python3
"""
Nuclei Scanner for Shield4U
Core vulnerability scanning functionality using Nuclei
"""

import json
import subprocess
import tempfile
import os
import logging
from typing import Dict, List, Optional, Any, Tuple
import time
from urllib.parse import urlparse

from config import Config
from utils.logger import setup_logger

logger = setup_logger(__name__)

class NucleiScanner:
    """Main Nuclei scanner engine"""
    
    def __init__(self):
        self.config = Config
        self.nuclei_binary = self.config.NUCLEI_BINARY_PATH
        
        # Verify Nuclei installation
        self._verify_nuclei_installation()
    
    def _verify_nuclei_installation(self) -> bool:
        """Verify that Nuclei is properly installed"""
        try:
            result = subprocess.run(
                [self.nuclei_binary, '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                logger.info(f"Nuclei version: {result.stdout.strip()}")
                return True
            else:
                raise Exception(f"Nuclei version check failed: {result.stderr}")
                
        except Exception as e:
            logger.error(f"Nuclei installation verification failed: {str(e)}")
            raise Exception(f"Nuclei is not properly installed: {str(e)}")
    
    def get_nuclei_version(self) -> str:
        """Get Nuclei version"""
        try:
            result = subprocess.run(
                [self.nuclei_binary, '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return "unknown"
                
        except Exception as e:
            logger.error(f"Error getting Nuclei version: {str(e)}")
            return "error"
    
    def run_scan(self, target_url: str, scan_rules: Dict[str, Any], analysis_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Run vulnerability scan on target URL
        
        Args:
            target_url: URL to scan
            scan_rules: Dictionary containing scan rules and YAML templates from LLM analysis
            analysis_id: ID of the analysis result
            
        Returns:
            List of vulnerability findings
        """
        try:
            logger.info(f"Starting Nuclei scan on {target_url}")
            
            # Validate target URL
            is_valid, validation_error = self.validate_target(target_url)
            if not is_valid:
                raise Exception(f"Invalid target URL: {validation_error}")
            
            # Extract YAML templates from scan_rules
            yaml_templates = ""
            if isinstance(scan_rules, dict) and scan_rules:
                yaml_templates = scan_rules.get('yaml_templates', '')
            
            # Generate Nuclei command with YAML templates
            nuclei_cmd = self._build_nuclei_command_with_yaml(target_url, yaml_templates)
            
            # Run Nuclei scan
            scan_results = self._execute_nuclei_scan(nuclei_cmd)
            
            # Process and format results
            processed_results = self._process_scan_results(scan_results, target_url, analysis_id)
            
            logger.info(f"Scan completed: {len(processed_results)} vulnerabilities found")
            return processed_results
            
        except Exception as e:
            logger.error(f"Error running Nuclei scan: {str(e)}")
            raise e
    
    def run_custom_scan(self, target_url: str, template_list: List[str], custom_templates: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Run custom scan with specified templates
        
        Args:
            target_url: URL to scan
            template_list: List of template names/categories
            custom_templates: Custom template definitions
            
        Returns:
            List of vulnerability findings
        """
        try:
            logger.info(f"Starting custom Nuclei scan on {target_url}")
            
            # Create temporary files for custom templates if provided
            custom_template_files = []
            if custom_templates:
                custom_template_files = self._create_custom_template_files(custom_templates)
            
            try:
                # Build command with specified templates
                nuclei_cmd = self._build_custom_nuclei_command(target_url, template_list, custom_template_files)
                
                # Execute scan
                scan_results = self._execute_nuclei_scan(nuclei_cmd)
                
                # Process results
                processed_results = self._process_scan_results(scan_results, target_url)
                
                return processed_results
                
            finally:
                # Clean up custom template files
                for temp_file in custom_template_files:
                    try:
                        os.unlink(temp_file)
                    except Exception as e:
                        logger.warning(f"Failed to remove temporary template file: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error running custom scan: {str(e)}")
            raise e
    
    def validate_target(self, target_url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate target URL for scanning
        
        Args:
            target_url: URL to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Parse URL
            parsed = urlparse(target_url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                return False, "URL must use http or https scheme"
            
            # Check hostname
            if not parsed.hostname:
                return False, "URL must have a valid hostname"
            
            # Check for private/local addresses
            if self._is_private_address(parsed.hostname):
                return False, "Cannot scan private/local addresses"
            
            # Test connectivity
            connectivity_result = self._test_connectivity(target_url)
            if not connectivity_result[0]:
                return False, f"Target not reachable: {connectivity_result[1]}"
            
            return True, None
            
        except Exception as e:
            return False, f"URL validation error: {str(e)}"
    
    def _build_nuclei_command(self, target_url: str, scan_rules: Dict[str, Any]) -> List[str]:
        """Build Nuclei command based on scan rules"""
        cmd = [self.nuclei_binary]
        
        # Basic options
        cmd.extend(['-target', target_url])
        cmd.extend(['-jsonl'])
        cmd.extend(['-silent'])
        cmd.extend(['-no-color'])
        
        # Concurrency and performance
        cmd.extend(['-c', str(self.config.NUCLEI_CONFIG['concurrency'])])
        cmd.extend(['-rl', str(self.config.NUCLEI_CONFIG['rate_limit'])])
        cmd.extend(['-timeout', str(self.config.NUCLEI_CONFIG['timeout'])])
        cmd.extend(['-retries', str(self.config.NUCLEI_CONFIG['retries'])])
        
        # Template selection based on scan rules
        if scan_rules and 'templates' in scan_rules:
            templates = scan_rules['templates']
            if isinstance(templates, list) and templates:
                # Use specific templates
                for template in templates:
                    cmd.extend(['-t', template])
            elif isinstance(templates, str):
                cmd.extend(['-t', templates])
        else:
            # Use default template categories for comprehensive scan
            cmd.extend(['-t', self.config.NUCLEI_TEMPLATES_PATH])
        
        # Severity filtering
        if 'severity' in scan_rules:
            severity = scan_rules['severity']
            cmd.extend(['-severity', severity])
        else:
            cmd.extend(['-severity', self.config.MIN_SEVERITY])
        
        # Custom headers if specified
        if 'headers' in scan_rules:
            headers = scan_rules['headers']
            for header_name, header_value in headers.items():
                cmd.extend(['-H', f"{header_name}: {header_value}"])
        
        # Cookies if specified
        if 'cookies' in scan_rules:
            cookies = scan_rules['cookies']
            if isinstance(cookies, dict):
                cookie_string = '; '.join([f"{k}={v}" for k, v in cookies.items()])
                cmd.extend(['-H', f"Cookie: {cookie_string}"])
        
        return cmd
    
    def _build_nuclei_command_with_yaml(self, target_url: str, yaml_templates: str) -> List[str]:
        """Build Nuclei command with YAML template strings"""
        try:
            # Create temporary file for YAML templates
            temp_template_file = None
            if yaml_templates and yaml_templates.strip():
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                    f.write(yaml_templates)
                    temp_template_file = f.name
                    logger.info(f"Created temporary template file: {temp_template_file}")
            
            cmd = [self.nuclei_binary]
            
            # Basic options
            cmd.extend(['-target', target_url])
            cmd.extend(['-jsonl'])
            cmd.extend(['-silent'])
            cmd.extend(['-no-color'])
            
            # Concurrency and performance
            cmd.extend(['-c', str(self.config.NUCLEI_CONFIG['concurrency'])])
            cmd.extend(['-rl', str(self.config.NUCLEI_CONFIG['rate_limit'])])
            cmd.extend(['-timeout', str(self.config.NUCLEI_CONFIG['timeout'])])
            cmd.extend(['-retries', str(self.config.NUCLEI_CONFIG['retries'])])
            
            # Use custom template if available, otherwise use default templates
            if temp_template_file:
                cmd.extend(['-t', temp_template_file])
                # Store temp file for cleanup
                self._temp_files = getattr(self, '_temp_files', [])
                self._temp_files.append(temp_template_file)
            else:
                # Fallback to default templates
                cmd.extend(['-t', self.config.NUCLEI_TEMPLATES_PATH])
                logger.warning("No YAML templates provided, using default templates")
            
            return cmd
            
        except Exception as e:
            logger.error(f"Error building Nuclei command with YAML: {str(e)}")
            # Fallback to basic scan
            return self._build_basic_nuclei_command(target_url)
    
    def _build_basic_nuclei_command(self, target_url: str) -> List[str]:
        """Build basic Nuclei command for fallback"""
        cmd = [self.nuclei_binary]
        cmd.extend(['-target', target_url])
        cmd.extend(['-jsonl'])
        cmd.extend(['-silent'])
        cmd.extend(['-no-color'])
        cmd.extend(['-c', '10'])
        cmd.extend(['-rl', '150'])
        cmd.extend(['-severity', 'medium,high,critical'])
        return cmd
    
    def _build_custom_nuclei_command(self, target_url: str, template_list: List[str], custom_template_files: List[str] = None) -> List[str]:
        """Build Nuclei command for custom scan"""
        cmd = [self.nuclei_binary]
        
        # Basic options
        cmd.extend(['-target', target_url])
        cmd.extend(['-jsonl'])
        cmd.extend(['-silent'])
        cmd.extend(['-no-color'])
        
        # Performance settings
        cmd.extend(['-c', str(self.config.NUCLEI_CONFIG['concurrency'])])
        cmd.extend(['-rl', str(self.config.NUCLEI_CONFIG['rate_limit'])])
        
        # Add templates
        for template in template_list:
            # Check if it's a category or specific template
            if template in self.config.DEFAULT_TEMPLATE_CATEGORIES:
                template_path = os.path.join(self.config.NUCLEI_TEMPLATES_PATH, template)
                cmd.extend(['-t', template_path])
            else:
                # Assume it's a specific template
                cmd.extend(['-t', template])
        
        # Add custom templates
        if custom_template_files:
            for template_file in custom_template_files:
                cmd.extend(['-t', template_file])
        
        return cmd
    
    def _execute_nuclei_scan(self, nuclei_cmd: List[str]) -> List[str]:
        """Execute Nuclei scan and return results"""
        try:
            logger.info(f"Executing command: {' '.join(['nuclei'] + nuclei_cmd[1:])}")  # Hide binary path
            
            start_time = time.time()
            
            # Execute Nuclei
            result = subprocess.run(
                nuclei_cmd,
                capture_output=True,
                text=True,
                timeout=self.config.SCAN_TIMEOUT
            )
            
            execution_time = time.time() - start_time
            logger.info(f"Nuclei scan completed in {execution_time:.2f} seconds")
            
            # Clean up temporary files
            self._cleanup_temp_files()
            
            # Check for errors
            if result.returncode != 0 and result.stderr:
                logger.warning(f"Nuclei stderr: {result.stderr}")
            
            # Parse JSON results
            results = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            results.append(line.strip())
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse JSON line: {line} - {str(e)}")
            
            return results
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nuclei scan timed out after {self.config.SCAN_TIMEOUT} seconds")
            raise Exception("Scan timeout")
        except Exception as e:
            logger.error(f"Error executing Nuclei scan: {str(e)}")
            raise e
    
    def _process_scan_results(self, raw_results: List[str], target_url: str, analysis_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Process and format Nuclei scan results"""
        processed_results = []
        
        for result_line in raw_results:
            try:
                result_data = json.loads(result_line)
                
                # Extract vulnerability information
                vulnerability = {
                    'template_id': result_data.get('template-id', 'unknown'),
                    'template_path': result_data.get('template-path', ''),
                    'info': result_data.get('info', {}),
                    'type': result_data.get('type', 'unknown'),
                    'host': result_data.get('host', target_url),
                    'matched_at': result_data.get('matched-at', target_url),
                    'extracted_results': result_data.get('extracted-results', []),
                    'matcher_name': result_data.get('matcher-name', ''),
                    'timestamp': result_data.get('timestamp', time.time())
                }
                
                # Extract severity and other info details
                info = result_data.get('info', {})
                vulnerability.update({
                    'name': info.get('name', 'Unknown Vulnerability'),
                    'author': info.get('author', []),
                    'severity': info.get('severity', 'info').lower(),
                    'description': info.get('description', ''),
                    'reference': info.get('reference', []),
                    'tags': info.get('tags', []),
                    'classification': info.get('classification', {})
                })
                
                # Add analysis context if available
                if analysis_id:
                    vulnerability['analysis_id'] = analysis_id
                
                # Filter by minimum severity
                if self._meets_severity_threshold(vulnerability['severity']):
                    processed_results.append(vulnerability)
                
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse Nuclei result: {result_line} - {str(e)}")
            except Exception as e:
                logger.error(f"Error processing scan result: {str(e)}")
        
        return processed_results
    
    def _create_custom_template_files(self, custom_templates: List[Dict[str, Any]]) -> List[str]:
        """Create temporary files for custom templates"""
        template_files = []
        
        for template_data in custom_templates:
            try:
                # Create temporary file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                    template_content = template_data.get('template', '')
                    f.write(template_content)
                    template_files.append(f.name)
                    
            except Exception as e:
                logger.error(f"Failed to create custom template file: {str(e)}")
        
        return template_files
    
    def _cleanup_temp_files(self):
        """Clean up temporary template files"""
        temp_files = getattr(self, '_temp_files', [])
        for temp_file in temp_files:
            try:
                os.unlink(temp_file)
                logger.debug(f"Cleaned up temporary file: {temp_file}")
            except Exception as e:
                logger.warning(f"Failed to remove temporary file {temp_file}: {str(e)}")
        self._temp_files = []
    
    def _test_connectivity(self, target_url: str) -> Tuple[bool, Optional[str]]:
        """Test connectivity to target URL"""
        try:
            # Simple connectivity test using curl
            result = subprocess.run(
                ['curl', '-s', '--connect-timeout', '10', '--max-time', '30', '-I', target_url],
                capture_output=True,
                text=True,
                timeout=35
            )
            
            if result.returncode == 0:
                return True, None
            else:
                return False, "Connection failed"
                
        except Exception as e:
            return False, str(e)
    
    def _is_private_address(self, hostname: str) -> bool:
        """Check if hostname is a private/local address"""
        import ipaddress
        
        private_patterns = [
            'localhost',
            '127.',
            '10.',
            '172.16.',
            '172.17.',
            '172.18.',
            '172.19.',
            '172.20.',
            '172.21.',
            '172.22.',
            '172.23.',
            '172.24.',
            '172.25.',
            '172.26.',
            '172.27.',
            '172.28.',
            '172.29.',
            '172.30.',
            '172.31.',
            '192.168.'
        ]
        
        hostname_lower = hostname.lower()
        
        # Check patterns
        for pattern in private_patterns:
            if hostname_lower.startswith(pattern):
                return True
        
        # Try to parse as IP address
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except ValueError:
            pass
        
        return False
    
    def _meets_severity_threshold(self, severity: str) -> bool:
        """Check if vulnerability severity meets minimum threshold"""
        severity_level = self.config.SEVERITY_LEVELS.get(severity.lower(), 0)
        min_level = self.config.SEVERITY_LEVELS.get(self.config.MIN_SEVERITY.lower(), 0)
        return severity_level >= min_level