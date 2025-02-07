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