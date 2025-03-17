import re
from urllib.parse import urlparse, unquote, parse_qs
from typing import Optional


class Utils:
    """Utility functions for extracting information from events"""

    @staticmethod
    def get_browser(plugin: str) -> str:
        """Extract browser information from plugin string"""
        browsers = {
            "firefox": "Mozilla Firefox",
            "chrome": "Google Chrome",
            "edge": "Microsoft Edge",
            "safari": "Safari",
        }
        plugin_lower = plugin.lower()
        for key, value in browsers.items():
            if key in plugin_lower:
                return value
        return "Unknown Browser"

    @staticmethod
    def extract_url(evidence: str) -> str:
        """Extract URL from evidence string"""
        # First try to get URL before any parentheses
        url_match = evidence.split(" (")[0].strip()
        if url_match.startswith(("http://", "https://", "www.")):
            return url_match

        # If that fails, try to find URL in the full string
        url_pattern = r'https?://[^\s()"]+'
        match = re.search(url_pattern, evidence)
        if match:
            return match.group(0)

        return ""

    @staticmethod
    def extract_domain_from_url(evidence: str) -> str:
        """Extract domain from URL in evidence string"""
        # First get the URL
        url = Utils.extract_url(evidence)
        if url:
            try:
                return urlparse(url).netloc
            except:  # noqa: E722
                # Try to extract domain from Host field if present
                host_match = re.search(r"Host:\s*([^\s]+)", evidence)
                if host_match:
                    return host_match.group(1)

        return ""

    @staticmethod
    def get_query_params_from_url_where_key_is(url: str, key: str) -> Optional[str]:
        """Extract a specific query parameter value from a URL
        
        This function handles various URL formats and encoding schemes:
        - Standard query parameters (?key=value)
        - Multiple parameter instances (returns first)
        - URL-encoded values (+, %20, etc.)
        - Hash fragments (#)
        - Missing query parameters
        
        Args:
            url: The URL string to parse
            key: The query parameter key to find
            
        Returns:
            str or None: The decoded parameter value if found, None otherwise
            
        Examples:
            >>> Utils.get_query_params_from_url_where_key_is(
            ...     "https://www.google.com/search?q=python+programming&source=hp",
            ...     "q"
            ... )
            'python programming'
        """
        try:
            # First try to extract the query string
            # Handle both ? and # cases
            query_string = ""
            if "?" in url:
                query_string = url.split("?", 1)[1]
            elif "#" in url:
                query_string = url.split("#", 1)[1]
            else:
                return None

            # Split into components and remove any hash fragments
            if "#" in query_string:
                query_string = query_string.split("#", 1)[0]

            # Parse the query string
            params = parse_qs(query_string)

            # Look for our key
            if key in params:
                # Get first value if multiple exist
                value = params[key][0]
                
                # Decode the value
                decoded_value = unquote(value)
                
                # Replace any remaining '+' with spaces
                decoded_value = decoded_value.replace("+", " ")
                
                return decoded_value.strip()

            return None

        except Exception as e:
            print(f"Error parsing URL parameters: {str(e)}")
            return None

    @staticmethod
    def get_content_type_from_request(evidence: str) -> Optional[str]:
        """Extract Content-Type from an HTTP request/response evidence string.
        
        Args:
            evidence (str): The evidence string containing HTTP headers
            
        Returns:
            Optional[str]: The content type if found, None otherwise
            
        Example:
            >>> Utils.get_content_type_from_request("URL: https://example.com/img.png Content-Type: image/png")
            'image/png'
        """
        # Look for Content-Type header
        content_type_pattern = r'Content-Type:\s*([^;\s]+)'
        match = re.search(content_type_pattern, evidence, re.IGNORECASE)
        
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def get_url_from_request(evidence: str) -> Optional[str]:
        """Extract URL from an HTTP request/response evidence string.
        
        Args:
            evidence (str): The evidence string containing HTTP request info
            
        Returns:
            Optional[str]: The URL if found, None otherwise
            
        Example:
            >>> Utils.get_url_from_request("URL: https://example.com/img.png Content-Type: image/png")
            'https://example.com/img.png'
        """
        # First try to find explicit URL field
        url_pattern = r'URL:\s*(https?://[^\s]+)'
        match = re.search(url_pattern, evidence, re.IGNORECASE)
        
        if match:
            url = match.group(1)
            # Clean up URL by removing any trailing quotes or brackets
            url = re.sub(r'["\'\)]$', '', url)
            return url
            
        # Fallback to looking for any URL in the evidence
        url_pattern = r'(https?://[^\s"\'\)]+)'
        match = re.search(url_pattern, evidence)
        
        if match:
            return match.group(1)
            
        return None

    @staticmethod
    def get_filename_from_url(evidence: str) -> Optional[str]:
        """Extract filename from an evidence message string.
        
        This function extracts the filename from the 'Filename:' field in the evidence message.
        If not found, attempts to extract from the URL.
        
        Args:
            evidence (str): The evidence message containing the filename information
            
        Returns:
            Optional[str]: The filename if found, None otherwise
            
        Example:
            >>> Utils.get_filename_from_url("... Filename: image[1].png ...")
            'image[1].png'
        """
        try:
            # First try to find explicit Filename field
            filename_pattern = r'Filename:\s*([^\s]+)'
            match = re.search(filename_pattern, evidence)
            
            if match:
                return match.group(1)
                
            # If no explicit filename, try to extract from URL
            url = Utils.get_url_from_request(evidence)
            if url:
                # Parse the URL
                parsed = urlparse(url)
                path = parsed.path
                
                # Get last part of path
                filename = path.split('/')[-1]
                if filename:
                    # URL decode the filename
                    filename = unquote(filename)
                    # Remove any query parameters or fragments
                    filename = re.sub(r'[?#].*$', '', filename)
                    return filename
                    
        except Exception as e:
            print(f"Error extracting filename: {str(e)}")
            
        return None

        # IP Address Extraction Functions
    @staticmethod
    def extract_ip_from_evidence(evidence: str) -> str:
        """Extract IP address from evidence string"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, evidence)
        if match:
            return match.group(0)
        return "unknown"
    
    @staticmethod
    def extract_source_ip_from_evidence(evidence: str) -> str:
        """Extract source IP address from evidence string"""
        # Try to find 'source IP' or 'from' patterns first
        source_patterns = [
            r'source(?:\s+IP)?[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'src=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ]
        
        for pattern in source_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Fall back to any IP in the string
        return Utils.extract_ip_from_evidence(evidence)
    
    @staticmethod
    def extract_destination_ip_from_evidence(evidence: str) -> str:
        """Extract destination IP address from evidence string"""
        # Try to find destination patterns first
        dest_patterns = [
            r'dest(?:ination)?(?:\s+IP)?[=:]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'to\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'dst=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        ]
        
        for pattern in dest_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Fall back to second IP in the string if there are multiple
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', evidence)
        if len(ips) > 1:
            return ips[1]
        
        return "unknown"
    
    # Port Extraction Functions
    @staticmethod
    def extract_source_port_from_evidence(evidence: str) -> str:
        """Extract source port from evidence string"""
        port_patterns = [
            r'source\s+port[=:]\s*(\d+)',
            r'from\s+\S+\s+port\s+(\d+)',
            r'sport=(\d+)'
        ]
        
        for pattern in port_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return "unknown"
    
    @staticmethod
    def extract_destination_port_from_evidence(evidence: str) -> str:
        """Extract destination port from evidence string"""
        port_patterns = [
            r'dest(?:ination)?\s+port[=:]\s*(\d+)',
            r'to\s+\S+\s+port\s+(\d+)',
            r'dport=(\d+)',
            r'port\s+(\d+)'
        ]
        
        for pattern in port_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return "unknown"
    
    # Username Extraction Functions
    @staticmethod
    def extract_username_from_evidence(evidence: str) -> str:
        """Extract username from evidence string"""
        username_patterns = [
            r'user[=:\s]+([a-zA-Z0-9_-]+)',
            r'username[=:]\s*([a-zA-Z0-9_-]+)',
            r'account[=:]\s*([a-zA-Z0-9_-]+)',
            r'for\s+(?:user\s+)?([a-zA-Z0-9_-]+)',
            r'by\s+([a-zA-Z0-9_-]+)'
        ]
        
        for pattern in username_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match and match.group(1) not in ['root', 'invalid', 'unknown']:
                return match.group(1)
                
        # If we found no matches or only matched 'root', 'invalid', 'unknown'
        match = re.search(r'user[=:\s]+([a-zA-Z0-9_-]+)', evidence, re.IGNORECASE)
        if match:
            return match.group(1)
            
        return "unknown"
    
    @staticmethod
    def extract_source_user_from_evidence(evidence: str) -> str:
        """Extract source user from evidence string"""
        source_patterns = [
            r'by\s+([a-zA-Z0-9_-]+)',
            r'from\s+user\s+([a-zA-Z0-9_-]+)'
        ]
        
        for pattern in source_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return Utils.extract_username_from_evidence(evidence)
    
    @staticmethod
    def extract_target_user_from_evidence(evidence: str) -> str:
        """Extract target user from evidence string"""
        target_patterns = [
            r'for\s+user\s+([a-zA-Z0-9_-]+)',
            r'user=([a-zA-Z0-9_-]+)',
            r'to\s+([a-zA-Z0-9_-]+)'
        ]
        
        for pattern in target_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return "unknown"
    
    @staticmethod
    def extract_new_username_from_evidence(evidence: str) -> str:
        """Extract newly created username from evidence string"""
        new_user_patterns = [
            r'new\s+(?:user|account)\s+(?:\'|")?([a-zA-Z0-9_-]+)',
            r'add(?:ed|ing)?\s+(?:user|account)\s+(?:\'|")?([a-zA-Z0-9_-]+)',
            r'useradd\s+(?:\'|")?([a-zA-Z0-9_-]+)'
        ]
        
        for pattern in new_user_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return Utils.extract_username_from_evidence(evidence)
    
    @staticmethod
    def extract_creator_username_from_evidence(evidence: str) -> str:
        """Extract the username of account creator"""
        creator_patterns = [
            r'by\s+(?:user\s+)?([a-zA-Z0-9_-]+)'
        ]
        
        for pattern in creator_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match and match.group(1) != Utils.extract_new_username_from_evidence(evidence):
                return match.group(1)
                
        # Look for user ID (UID) in the evidence
        uid_match = re.search(r'uid=(\d+)', evidence, re.IGNORECASE)
        if uid_match:
            uid = uid_match.group(1)
            if uid == "0":
                return "root"
            return f"uid_{uid}"
            
        return "unknown"
    
    # Command Extraction Functions
    @staticmethod
    def extract_command_from_evidence(evidence: str) -> str:
        """Extract command executed from evidence string"""
        # Try to match COMMAND= or CMD= format
        cmd_patterns = [
            r'COMMAND=([^\s;]+(?:\s+[^;]+)?)',
            r'CMD=([^\s;]+(?:\s+[^;]+)?)',
            r'command="([^"]+)"'
        ]
        
        for pattern in cmd_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Try to match common command patterns
        executable_pattern = r'(?:executing|executed|running|spawned)\s+(?:command\s+)?([^\s;]+(?:\s+[^;]+)?)'
        match = re.search(executable_pattern, evidence, re.IGNORECASE)
        if match:
            return match.group(1)
        
        # Search for common commands typically logged
        common_cmds = [
            r'(sudo\s+[^\s;]+(?:\s+[^;]+)?)',
            r'(ssh\s+[^\s;]+(?:\s+[^;]+)?)',
            r'(scp\s+[^\s;]+(?:\s+[^;]+)?)',
            r'(chmod\s+[^\s;]+(?:\s+[^;]+)?)',
            r'(chown\s+[^\s;]+(?:\s+[^;]+)?)',
            r'(wget\s+[^\s;]+(?:\s+[^;]+)?)',
            r'(curl\s+[^\s;]+(?:\s+[^;]+)?)'
        ]
        
        for pattern in common_cmds:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return "unknown command"
    
    # Operation Extraction Functions
    @staticmethod
    def extract_operation_from_evidence(evidence: str) -> str:
        """Extract file operation from evidence string"""
        operations = {
            'created': ['created', 'added', 'new'],
            'modified': ['modified', 'changed', 'updated', 'wrote'],
            'deleted': ['deleted', 'removed', 'unlinked'],
            'accessed': ['accessed', 'read', 'opened'],
            'executed': ['executed', 'exec', 'run', 'spawn']
        }
        
        evidence_lower = evidence.lower()
        for op_type, keywords in operations.items():
            for keyword in keywords:
                if keyword in evidence_lower:
                    return op_type
                    
        return "accessed"  # Default if no specific operation is found
    
    # Network and HTTP Related Functions
    @staticmethod
    def extract_http_method_from_evidence(evidence: str) -> str:
        """Extract HTTP method from evidence string"""
        method_pattern = r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\b'
        match = re.search(method_pattern, evidence)
        if match:
            return match.group(1)
        return "unknown"
    
    @staticmethod
    def extract_uri_path_from_evidence(evidence: str) -> str:
        """Extract URI path from evidence string"""
        # Try to match standard HTTP request format
        uri_pattern = r'(?:GET|POST|PUT|DELETE|HEAD)\s+(/[^\s]*)'
        match = re.search(uri_pattern, evidence)
        if match:
            return match.group(1)
        
        # Try to match URI path in other contexts
        alt_patterns = [
            r'uri=(?:\'|")?(/[^\'"\s]+)',
            r'path=(?:\'|")?(/[^\'"\s]+)'
        ]
        
        for pattern in alt_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return "/"
    
    @staticmethod
    def extract_http_request_from_evidence(evidence: str) -> str:
        """Extract full HTTP request from evidence string"""
        # Try to match standard HTTP request format
        request_pattern = r'((?:GET|POST|PUT|DELETE|HEAD)\s+/[^\s]*(?:\s+HTTP/[\d.]+)?)'
        match = re.search(request_pattern, evidence)
        if match:
            return match.group(1)
            
        # If not found, construct from method and URI
        method = Utils.extract_http_method_from_evidence(evidence)
        uri = Utils.extract_uri_path_from_evidence(evidence)
        
        if method != "unknown" and uri != "/":
            return f"{method} {uri}"
            
        return evidence[:50] + "..." if len(evidence) > 50 else evidence
    
    @staticmethod
    def extract_process_name_from_evidence(evidence: str) -> str:
        """Extract process name from evidence string"""
        process_patterns = [
            r'process[=:]\s*([^\s:;]+)',
            r'command[=:]\s*([^\s:;]+)',
            r'exe[=:]\s*([^\s:;]+)'
        ]
        
        for pattern in process_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        # Look for well-known process names
        known_processes = [
            'sshd', 'httpd', 'apache2', 'nginx', 'bash', 'sh', 'python',
            'perl', 'ruby', 'java', 'php', 'systemd', 'crond', 'mysqld'
        ]
        
        for proc in known_processes:
            if f"{proc}[" in evidence or f"{proc}:" in evidence or f" {proc} " in evidence:
                return proc
                
        return "unknown"
    
    # Miscellaneous Special Purpose Extractors
    @staticmethod
    def extract_cron_details_from_evidence(evidence: str) -> str:
        """Extract cron job details from evidence string"""
        # Try to find cron command pattern
        cmd_pattern = r'CROND.*CMD\s+\(([^)]+)\)'
        match = re.search(cmd_pattern, evidence)
        if match:
            return match.group(1)
            
        # Try to find crontab file modification
        crontab_pattern = r'(crontab\s+(?:-[a-z]\s+)+)(?:for\s+user\s+)?([a-zA-Z0-9_-]+)?'
        match = re.search(crontab_pattern, evidence)
        if match:
            if match.group(2):
                return f"{match.group(1)} for user {match.group(2)}"
            return match.group(1)
            
        return "unknown cron activity"
    
    @staticmethod
    def extract_module_name_from_evidence(evidence: str) -> str:
        """Extract kernel module name from evidence string"""
        # Try to match insmod/modprobe pattern
        module_patterns = [
            r'(?:insmod|modprobe)\s+([^\s]+)\.ko',
            r'(?:insmod|modprobe)\s+([^\s]+)',
            r'module\s+([^\s]+)\s+loaded',
            r'Loading\s+module\s+([^\s:]+)'
        ]
        
        for pattern in module_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return "unknown module"
    
    @staticmethod
    def extract_destination_from_evidence(evidence: str) -> str:
        """Extract destination from data transfer evidence"""
        # Look for IP addresses or hostnames in common transfer commands
        dest_patterns = [
            r'(?:scp|sftp|rsync|rclone)[^@]+@([^:/\s]+)',
            r'(?:scp|sftp|rsync|rclone)[^:]+:([^/\s]+)',
            r'(?:wget|curl)\s+(?:https?://)?([^/\s]+)',
            r'to\s+(?:host\s+)?([^:/\s]+)'
        ]
        
        for pattern in dest_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        # Fall back to destination IP if found
        dest_ip = Utils.extract_destination_ip_from_evidence(evidence)
        if dest_ip != "unknown":
            return dest_ip
            
        return "unknown destination"
    
    @staticmethod
    def extract_file_size_from_evidence(evidence: str) -> str:
        """Extract file size from evidence string"""
        # Look for file size patterns
        size_patterns = [
            r'size[=:]\s*(\d+(?:\.\d+)?)\s*([KMG]B)?',
            r'(\d+(?:\.\d+)?)\s*([KMG]B)',
            r'transferred\s+(\d+(?:\.\d+)?)\s*([KMG]?B)?'
        ]
        
        for pattern in size_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                size = match.group(1)
                unit = match.group(2) if match.groupdict().get(2) else "B"
                return f"{size} {unit}"
                
        return "unknown size"
    
    @staticmethod
    def extract_groups_from_evidence(evidence: str) -> str:
        """Extract group information from user creation evidence"""
        group_patterns = [
            r'groups?=(?:\'|")?([^\'";]+)',
            r'added\s+to\s+groups?\s+(?:\'|")?([^\'";]+)',
            r'-G\s+([^\'";]+)'
        ]
        
        for pattern in group_patterns:
            match = re.search(pattern, evidence, re.IGNORECASE)
            if match:
                return match.group(1)
                
        # Check for specific privileges
        if "sudo" in evidence.lower():
            return "sudo"
        if "admin" in evidence.lower():
            return "admin"
        if "wheel" in evidence.lower():
            return "wheel"
            
        return "unknown groups"

