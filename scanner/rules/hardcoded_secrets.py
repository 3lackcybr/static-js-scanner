# scanner/rules/hardcoded_secrets.py
import re
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

class HardcodedSecretRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="Hardcoded Secret",
            cwe_id="CWE-798",
            description="API key, password, or token hardcoded in source."
        )
        self.secret_patterns = [
            (r'(api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', 'API Key'),
            (r'(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', 'Password'),
            (r'(secret|token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{10,})["\']', 'Secret/Token'),
            (r'(sk_[a-zA-Z0-9]{24,})', 'Stripe Secret Key'),
            (r'(ghp_[a-zA-Z0-9]{36})', 'GitHub Personal Access Token'),
        ]
    
    def detect(self, ast_node, file_path, code_lines):
        vulnerabilities = []
        # Also scan raw code lines for regex patterns
        for line_num, line in enumerate(code_lines, start=1):
            for pattern, secret_type in self.secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        vuln_type=self.vuln_type,
                        cwe_id=self.cwe_id,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=line.strip(),
                        description=f"Potential hardcoded {secret_type} found.",
                        remediation="Use environment variables or a secrets manager."
                    ))
                    break  # Only report once per line
        return vulnerabilities
