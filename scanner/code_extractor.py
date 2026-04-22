# scanner/code_extractor.py
from bs4 import BeautifulSoup
import re

class CodeExtractor:
    def __init__(self):
        self.raw_content = ""
    
    def extract_javascript(self, content):
        """Extract JavaScript from HTML/PHP or return plain JS."""
        self.raw_content = content
        
        # If content appears to be pure JavaScript, return it directly
        if not self._contains_markup(content):
            return content
        
        soup = BeautifulSoup(content, 'html.parser')
        scripts = []
        for script in soup.find_all('script'):
            if script.string:
                scripts.append(script.string)
        
        # Also try regex for PHP echoed scripts
        php_pattern = r'<\?php\s+echo\s+["\']<script[^>]*>(.*?)</script>["\']\s*;?\s*\?>'
        php_matches = re.findall(php_pattern, content, re.DOTALL | re.IGNORECASE)
        scripts.extend(php_matches)
        
        if scripts:
            return "\n".join(scripts)
        # Fallback: return original content (might be pure JS with some noise)
        return content
    
    def _contains_markup(self, content):
        """Check if content contains HTML/PHP tags."""
        markers = ['<html', '<body', '<div', '<script', '<?php', '<%']
        content_lower = content.lower()
        return any(m in content_lower for m in markers)
    
    def is_javascript_present(self):
        extracted = self.extract_javascript(self.raw_content)
        return len(extracted.strip()) > 0
