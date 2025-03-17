"""
Turnstile Client for interacting with the Turnstile Solver API
"""

import logging
import requests
from typing import Dict, Optional, Union
from urllib.parse import urlparse


class TurnstileClient:
    """
    Client for interacting with the Turnstile Solver API
    """

    def __init__(self, api_url: str = "http://127.0.0.1:5000", shared_browser=None):
        """
        Initialize the client
        
        Args:
            api_url: URL of the Turnstile Solver API
            shared_browser: Optional shared browser instance to use instead of creating a new one
        """
        self.api_url = api_url
        self.shared_browser = shared_browser
        self.logger = logging.getLogger("TurnstileClient")

    def solve(
        self, 
        url: str, 
        sitekey: str, 
        invisible: bool = False, 
        proxy: Optional[str] = None,
        timeout: int = 600
    ) -> Dict[str, Union[str, None]]:
        """
        Solve a Turnstile challenge by making a request to the API
        
        Args:
            url: The URL containing the turnstile or any identifier string
            sitekey: The sitekey for the turnstile
            invisible: Whether the turnstile is invisible
            proxy: Optional proxy to use (format: "http://user:pass@host:port")
            timeout: Request timeout in seconds
            
        Returns:
            Dict with status and token (or error message)
        """
        # Validate URL format
        if not url.startswith(("http://", "https://")) and "://" not in url:
            # Try to make it a valid URL for display purposes
            url = f"https://{url}"
        
        # Check if API URL is valid
        if not self.api_url:
            return {"status": "error", "message": "API URL not configured", "token": None}
            
        # Prepare request
        endpoint = f"{self.api_url}/solve"
        payload = {
            "url": url,
            "sitekey": sitekey,
            "invisible": invisible,
            "use_shared_browser": self.shared_browser is not None
        }
        
        # Add proxy if provided
        if proxy:
            payload["proxy"] = proxy
            
        self.logger.info(f"Solving Turnstile for {url} with sitekey {sitekey}")
        
        try:
            # Make API request
            response = requests.post(
                endpoint, 
                json=payload,
                timeout=timeout
            )
            
            # Check for successful response
            if response.status_code == 200:
                result = response.json()
                if result.get("status") == "success" and result.get("token"):
                    self.logger.info(f"Successfully solved Turnstile: {result['token'][:10]}...")
                    return result
                else:
                    self.logger.error(f"API returned error: {result.get('message', 'Unknown error')}")
                    return {"status": "error", "message": result.get("message", "Unknown error"), "token": None}
            else:
                self.logger.error(f"API request failed with status {response.status_code}")
                return {"status": "error", "message": f"API request failed with status {response.status_code}", "token": None}
                
        except requests.RequestException as e:
            self.logger.error(f"Error connecting to Turnstile Solver API: {str(e)}")
            return {"status": "error", "message": f"Connection error: {str(e)}", "token": None}
        
    def extract_sitekey(self, html_content: str) -> Optional[str]:
        """
        Extract Turnstile sitekey from HTML content
        
        Args:
            html_content: HTML content to search for sitekey
            
        Returns:
            Sitekey string if found, None otherwise
        """
        import re
        
        # Common patterns for Turnstile sitekeys in HTML
        patterns = [
            r'data-sitekey="([0-9A-Za-z_-]+)"',
            r"data-sitekey='([0-9A-Za-z_-]+)'",
            r'sitekey:\s*["\']([0-9A-Za-z_-]+)["\']',
            r'sitekey=([0-9A-Za-z_-]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content)
            if matches:
                return matches[0]
                
        return None
        
    def is_api_available(self) -> bool:
        """
        Check if the Turnstile Solver API is available
        
        Returns:
            True if API is available, False otherwise
        """
        try:
            response = requests.get(self.api_url, timeout=5)
            return response.status_code < 500  # Accept any non-5xx response
        except requests.RequestException:
            return False