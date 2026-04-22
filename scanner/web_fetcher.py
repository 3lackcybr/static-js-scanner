# scanner/web_fetcher.py
import requests
from urllib.parse import urljoin, urlparse
import re
import time

class WebFetcher:
    """Fetches HTML content from URLs and downloads linked JavaScript files."""
    
    def __init__(self, timeout=30, max_retries=2):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; StaticSecurityScanner/1.0)'
        })
    
    def _request_with_retry(self, url):
        """Perform GET request with retry logic."""
        last_exception = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()
                return response
            except requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
            except requests.exceptions.HTTPError as e:
                # Don't retry on 404 or other client errors
                raise ConnectionError(f"HTTP error {e.response.status_code}: {url}")
            except requests.exceptions.RequestException as e:
                last_exception = e
                break
        raise ConnectionError(f"Failed to fetch '{url}' after {self.max_retries+1} attempts: {last_exception}")
    
    def fetch(self, url):
        """Fetch HTML content from a URL."""
        response = self._request_with_retry(url)
        return response.text
    
    def fetch_js(self, url):
        """Fetch JavaScript file content directly from a URL."""
        response = self._request_with_retry(url)
        return response.text
    
    def download_linked_js(self, html_content, base_url):
        """Extract and download all linked .js files from HTML."""
        script_urls = self._extract_script_srcs(html_content, base_url)
        js_contents = []
        for js_url in script_urls:
            try:
                js_content = self.fetch_js(js_url)
                js_contents.append(js_content)
            except ConnectionError:
                continue
        return js_contents
    
    def _extract_script_srcs(self, html_content, base_url):
        """Extract src attributes from <script> tags."""
        pattern = r'<script[^>]+src=["\']([^"\']+\.js)["\'][^>]*>'
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        urls = []
        for match in matches:
            full_url = urljoin(base_url, match)
            urls.append(full_url)
        return urls
