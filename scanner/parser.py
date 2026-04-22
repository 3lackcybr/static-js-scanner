# scanner/parser.py
import pyjsparser

class Parser:
    """Parses JavaScript code into an Abstract Syntax Tree (AST)."""
    
    def parse_to_ast(self, js_code):
        """Convert JavaScript string to AST using pyjsparser."""
        try:
            return pyjsparser.parse(js_code)
        except Exception as e:
            raise SyntaxError(f"JavaScript syntax error: {e}")
