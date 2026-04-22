# scanner/core_engine.py
from scanner.rules import SQLInjectionRule, XSSRule, CommandInjectionRule, HardcodedSecretRule
from scanner.cwe_mapper import CWEMapper

class CoreAnalysisEngine:
    def __init__(self):
        self.rules = [
            SQLInjectionRule(),
            XSSRule(),
            CommandInjectionRule(),
            HardcodedSecretRule()
        ]
        self.cwe_mapper = CWEMapper()
    
    def scan(self, ast, file_path, code_lines):
        vulnerabilities = []
        for rule in self.rules:
            found = rule.detect(ast, file_path, code_lines)
            vulnerabilities.extend(found)
        
        # Enrich with CWE details if not already set (some rules already set them)
        for vuln in vulnerabilities:
            details = self.cwe_mapper.get_cwe_details(vuln.type.lower().replace(' ', '_').replace('(', '').replace(')', ''))
            if vuln.cwe_id == 'CWE-Unknown':
                vuln.cwe_id = details.get('cwe_id', 'CWE-Unknown')
            if not vuln.description:
                vuln.description = details.get('description', '')
            if not vuln.remediation:
                vuln.remediation = details.get('remediation', '')
        
        return vulnerabilities
