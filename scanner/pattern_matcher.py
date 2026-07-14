# scanner/pattern_matcher.py
import json
import os
import re
from scanner.vulnerability import Vulnerability

class PatternMatcher:
    """Scans code lines against a comprehensive vulnerability pattern database."""
    
    def __init__(self, patterns_path=None):
        if patterns_path is None:
            patterns_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'vulnerability_patterns.json')
        with open(patterns_path, 'r') as f:
            self.patterns = json.load(f)
    
    def scan_lines(self, file_path, code_lines):
        """
        Returns a list of Vulnerability objects for patterns matched in the given lines.
        The type mapping is handled by the pattern category names (sql_injection -> SQL Injection, etc.)
        """
        vulnerabilities = []
        # Map of category name to CWE and display info
        category_info = {
            'sql_injection': ('SQL Injection', 'CWE-89', 'Use parameterized queries or prepared statements.'),
            'xss': ('Cross-Site Scripting (XSS)', 'CWE-79', 'Use safe DOM methods or sanitize input.'),
            'command_injection': ('Command Injection', 'CWE-78', 'Avoid executing commands with user input.'),
            'hardcoded_secrets': ('Hardcoded Secret', 'CWE-798', 'Use environment variables or a secrets manager.'),
            'eval_injection': ('Insecure Use of eval()', 'CWE-95', 'Avoid eval() with dynamic input.'),
        }
        
        for category, patterns in self.patterns.items():
            vuln_type, cwe_id, remediation = category_info.get(category, (category, 'N/A', ''))
            for i, line in enumerate(code_lines, start=1):
                for pat in patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        # Only report once per line per category (simple dedup)
                        vuln = Vulnerability(
                            vuln_type=vuln_type,
                            cwe_id=cwe_id,
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description=f"Pattern match for {vuln_type}: {pat}",
                            remediation=remediation
                        )
                        # Prevent duplicate reports for the same line + category
                        already = any(v.file_path == file_path and v.line_number == i and v.type == vuln_type
                                      for v in vulnerabilities)
                        if not already:
                            vulnerabilities.append(vuln)
                        break  # move to next line once a pattern in this category matches
        return vulnerabilities