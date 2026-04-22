# scanner/rules/sql_injection.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

class SQLInjectionRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="SQL Injection",
            cwe_id="CWE-89",
            description="User input concatenated into SQL query."
        )
    
    def detect(self, ast_node, file_path, code_lines):
        vulnerabilities = []
        self._traverse(ast_node, file_path, code_lines, vulnerabilities)
        return vulnerabilities
    
    def _traverse(self, node, file_path, code_lines, vulnerabilities):
        if isinstance(node, dict):
            if node.get('type') == 'ExpressionStatement':
                expr = node.get('expression', {})
                if expr.get('type') == 'AssignmentExpression':
                    right = expr.get('right', {})
                    if right.get('type') == 'BinaryExpression' and right.get('operator') == '+':
                        left = right.get('left', {})
                        right_val = right.get('right', {})
                        if self._is_string_containing_sql(left) or self._is_string_containing_sql(right_val):
                            line_num = node.get('loc', {}).get('start', {}).get('line', 1)
                            snippet = self._get_snippet(code_lines, line_num)
                            vulnerabilities.append(Vulnerability(
                                vuln_type=self.vuln_type,
                                cwe_id=self.cwe_id,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=snippet,
                                description=self.description,
                                remediation="Use parameterized queries or prepared statements."
                            ))
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    self._traverse(value, file_path, code_lines, vulnerabilities)
        elif isinstance(node, list):
            for item in node:
                self._traverse(item, file_path, code_lines, vulnerabilities)
    
    def _is_string_containing_sql(self, node):
        if isinstance(node, dict) and node.get('type') == 'Literal':
            value = node.get('value', '')
            return isinstance(value, str) and any(
                keyword in value.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP']
            )
        return False
    
    def _get_snippet(self, code_lines, line_num):
        if line_num <= len(code_lines):
            return code_lines[line_num - 1].strip()
        return ""
