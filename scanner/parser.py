import subprocess
import json
import os

class Parser:
    def __init__(self):
        self.script_path = os.path.join(os.path.dirname(__file__), 'parser_script.js')

    def parse_to_ast(self, js_code):
        result = subprocess.run(
            ['node', self.script_path],
            input=js_code,
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            raise SyntaxError(result.stderr.strip())
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            raise SyntaxError("Failed to parse AST output")
