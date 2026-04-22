# scanner/rules/command_injection.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

class CommandInjectionRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="Command Injection",
            cwe_id="CWE-78",
            description="User input passed to exec() or similar function."
        )
        self.dangerous_funcs = ['exec', 'execSync', 'spawn', 'execFile', 'system']
    
    def detect(self, ast_node, file_path, code_lines):
        vulnerabilities = []
        self._traverse(ast_node, file_path, code_lines, vulnerabilities)
        return vulnerabilities
    
    def _traverse(self, node, file_path, code_lines, vulnerabilities):
        if isinstance(node, dict):
            if node.get('type') == 'CallExpression':
                callee = node.get('callee', {})
                func_name = None
                if callee.get('type') == 'Identifier':
                    func_name = callee.get('name')
                elif callee.get('type') == 'MemberExpression':
                    func_name = callee.get('property', {}).get('name')
                
                if func_name in self.dangerous_funcs:
                    args = node.get('arguments', [])
                    if args and self._contains_concatenation(args[0]):
                        line_num = node.get('loc', {}).get('start', {}).get('line', 1)
                        snippet = self._get_snippet(code_lines, line_num)
                        vulnerabilities.append(Vulnerability(
                            vuln_type=self.vuln_type,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=snippet,
                            description=self.description,
                            remediation="Avoid using exec() with user input. Use allowlists or escape arguments."
                        ))
            for key, value in node.items():
                if isinstance(value, (dict, list)):
                    self._traverse(value, file_path, code_lines, vulnerabilities)
        elif isinstance(node, list):
            for item in node:
                self._traverse(item, file_path, code_lines, vulnerabilities)
    
    def _contains_concatenation(self, node):
        if isinstance(node, dict):
            if node.get('type') == 'BinaryExpression' and node.get('operator') == '+':
                return True
        return False
    
    def _get_snippet(self, code_lines, line_num):
        if line_num <= len(code_lines):
            return code_lines[line_num - 1].strip()
        return ""
