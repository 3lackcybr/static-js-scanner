# scanner/rules/base_rule.py
from abc import ABC, abstractmethod

class VulnerabilityRule(ABC):
    """Abstract base class for all vulnerability detection rules."""
    
    def __init__(self, vuln_type, cwe_id, description):
        self.vuln_type = vuln_type
        self.cwe_id = cwe_id
        self.description = description
    
    @abstractmethod
    def detect(self, ast_node, file_path, code_lines):
        """Return a list of Vulnerability objects found in the AST."""
        pass
