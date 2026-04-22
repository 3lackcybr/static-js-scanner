# scanner/input_handler.py
import os
from .web_fetcher import WebFetcher

class InputHandler:
    def __init__(self):
        self.web_fetcher = WebFetcher()
    
    def accept_input(self, source):
        """
        Determine if source is a file path or URL.
        Returns: (content, source_type, base_url_or_path)
        """
        if source.startswith(('http://', 'https://')):
            # It's a URL
            content = self.web_fetcher.fetch(source)
            # Also download linked JS files and append their content
            linked_js = self.web_fetcher.download_linked_js(content, source)
            combined_js = content + "\n" + "\n".join(linked_js)
            return combined_js
        elif os.path.exists(source):
            # It's a local file
            with open(source, 'r', encoding='utf-8') as f:
                content = f.read()
            return content
        else:
            raise ValueError(f"Invalid source: {source}")
