import esprima

class Parser:
    def parse_to_ast(self, js_code):
        try:
            ast = esprima.parseScript(js_code, loc=True)
            return ast.toDict()
        except Exception as e:
            raise SyntaxError(str(e))
