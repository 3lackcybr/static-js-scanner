 # scanner/rules/eval_injection.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

USER_INPUT_SOURCES = {
    'location.search', 'location.hash', 'location.href',
    'document.cookie', 'document.referrer',
    'window.name',
    'req.query', 'req.params', 'req.body', 'req.cookies',
    'request.url', 'request.args', 'request.json',
}

class EvalInjectionRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="Insecure Use of eval()",
            cwe_id="CWE-95",
            description="Dynamically constructed argument passed to eval()."
        )

    def detect(self, ast, file_path, code_lines, initial_tainted=None):
        vulns = []
        taint_start = initial_tainted if initial_tainted else set()
        self._walk(ast, file_path, code_lines, vulns, parent_type=None,
                   tainted_vars=taint_start, taint_depth=0)
        return vulns

    def _walk(self, node, file_path, code_lines, vulns, parent_type, tainted_vars, taint_depth):
        if not isinstance(node, dict):
            return tainted_vars, taint_depth

        node_type = node.get('type')
        new_tainted = set(tainted_vars)
        new_depth = taint_depth

        if node_type == 'AssignmentExpression':
            left = node.get('left')
            right = node.get('right')
            if left and left.get('type') == 'Identifier':
                var_name = left.get('name')
                if self._is_from_user_input(right):
                    new_tainted.add(var_name)
                    new_depth = 1
                elif self._references_tainted_var(right, tainted_vars):
                    new_tainted.add(var_name)
                    new_depth = taint_depth + 1
                else:
                    new_tainted.discard(var_name)
        elif node_type == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                init = decl.get('init')
                if init and self._is_from_user_input(init):
                    var_id = decl.get('id')
                    if var_id and var_id.get('type') == 'Identifier':
                        new_tainted.add(var_id.get('name'))
                        new_depth = 1
                elif init and self._references_tainted_var(init, tainted_vars):
                    var_id = decl.get('id')
                    if var_id and var_id.get('type') == 'Identifier':
                        new_tainted.add(var_id.get('name'))
                        new_depth = taint_depth + 1

        if node_type == 'CallExpression':
            callee = node.get('callee')
            if callee and callee.get('type') == 'Identifier' and callee.get('name') == 'eval':
                args = node.get('arguments', [])
                if args and not self._is_literal_string(args[0]) and \
                   self._references_tainted_var(args[0], new_tainted):
                    score = 95 if new_depth == 1 else 75
                    if score >= 50:
                        line = node['loc']['start']['line']
                        snippet = code_lines[line-1].strip() if line-1 < len(code_lines) else ''
                        vars_used = self._extract_identifiers(args[0])
                        var_names = ', '.join(set(vars_used)) if vars_used else 'a dynamic expression'
                        desc = f"eval() called with {var_names}."
                        remed = "Avoid eval(). Use JSON.parse() or a safe parser."
                        vulns.append(Vulnerability(
                            vuln_type=self.vuln_type,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=line,
                            code_snippet=snippet,
                            description=desc,
                            remediation=remed,
                            confidence_score=score
                        ))

        for key, value in node.items():
            if isinstance(value, dict):
                t, d = self._walk(value, file_path, code_lines, vulns, node_type, new_tainted, new_depth)
                new_tainted.update(t)
                new_depth = max(new_depth, d)
            elif isinstance(value, list):
                for item in value:
                    t, d = self._walk(item, file_path, code_lines, vulns, node_type, new_tainted, new_depth)
                    new_tainted.update(t)
                    new_depth = max(new_depth, d)
        return new_tainted, new_depth

    # ----- helpers -----
    def _is_literal_string(self, node):
        return isinstance(node, dict) and node.get('type') == 'Literal' and isinstance(node.get('value'), str)

    def _is_from_user_input(self, node):
        if isinstance(node, dict):
            if node.get('type') == 'MemberExpression':
                obj = node.get('object')
                prop = node.get('property')
                if obj and prop:
                    obj_name = self._get_full_name(obj)
                    prop_name = self._get_name(prop)
                    if obj_name in USER_INPUT_SOURCES:
                        return True
                    full = f"{obj_name}.{prop_name}"
                    if full in USER_INPUT_SOURCES:
                        return True
            if node.get('type') == 'CallExpression':
                callee = node.get('callee')
                if callee:
                    full = self._get_full_name(callee)
                    if full in USER_INPUT_SOURCES:
                        return True
        return False

    def _references_tainted_var(self, node, tainted_vars):
        if isinstance(node, dict):
            if node.get('type') == 'Identifier' and node.get('name') in tainted_vars:
                return True
            for value in node.values():
                if self._references_tainted_var(value, tainted_vars):
                    return True
        elif isinstance(node, list):
            for item in node:
                if self._references_tainted_var(item, tainted_vars):
                    return True
        return False

    def _extract_identifiers(self, node):
        names = []
        if isinstance(node, dict):
            if node.get('type') == 'Identifier':
                names.append(node.get('name', ''))
            for value in node.values():
                names.extend(self._extract_identifiers(value))
        elif isinstance(node, list):
            for item in node:
                names.extend(self._extract_identifiers(item))
        return names

    def _get_name(self, node):
        if isinstance(node, dict) and node.get('type') == 'Identifier':
            return node.get('name', '')
        return ''

    def _get_full_name(self, node):
        if isinstance(node, dict):
            if node.get('type') == 'MemberExpression':
                obj = node.get('object')
                prop = node.get('property')
                obj_name = self._get_full_name(obj) if obj else ''
                prop_name = prop.get('name') if isinstance(prop, dict) else ''
                return f"{obj_name}.{prop_name}" if obj_name else prop_name
            elif node.get('type') == 'Identifier':
                return node.get('name', '')
        return ''