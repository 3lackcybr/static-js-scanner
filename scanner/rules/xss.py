# scanner/rules/xss.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

class XSSRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="Cross-Site Scripting (XSS)",
            cwe_id="CWE-79",
            description="User input assigned to innerHTML or document.write()."
        )
    
    def detect(self, ast_node, file_path, code_lines):
        vulnerabilities = []
        self._traverse(ast_node, file_path, code_lines, vulnerabilities)
        return vulnerabilities
    
    def _traverse(self, node, file_path, code_lines, vulnerabilities):
        if isinstance(node, dict):
            if node.get('type') == 'AssignmentExpression':
                left = node.get('left', {})
                if self._is_innerhtml(left) or self._is_document_write(left):
                    line_num = node.get('loc', {}).get('start', {}).get('line', 1)
                    snippet = self._get_snippet(code_lines, line_num)
                    vulnerabilities.append(Vulnerability(
                        vuln_type=self.vuln_type,
                        cwe_id=self.cwe_id,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet,
                        description=self.description,
                        remediation="Use textContent instead of innerHTML, or sanitize with DOMPurify."
                    ))
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    self._traverse(value, file_path, code_lines, vulnerabilities)
        elif isinstance(node, list):
            for item in node:
                self._traverse(item, file_path, code_lines, vulnerabilities)
    
    def _is_innerhtml(self, node):
        if node.get('type') == 'MemberExpression':
            prop = node.get('property', {})
            return prop.get('name') == 'innerHTML'
        return False
    
    def _is_document_write(self, node):
        if node.get('type') == 'CallExpression':
            callee = node.get('callee', {})
            if callee.get('type') == 'MemberExpression':
                obj = callee.get('object', {})
                prop = callee.get('property', {})
                return obj.get('name') == 'document' and prop.get('name') == 'write'
        return False
    
    def _get_snippet(self, code_lines, line_num):
        if line_num <= len(code_lines):
            return code_lines[line_num - 1].strip()
        return ""
