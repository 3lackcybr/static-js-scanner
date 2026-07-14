 # scanner/rules/xss.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

USER_INPUT_SOURCES = {
    'location.search', 'location.hash', 'location.href',
    'document.cookie', 'document.referrer',
    'window.name',
    'req.query', 'req.params', 'req.body', 'req.cookies',
    'request.url', 'request.args', 'request.json',
}

XSS_SANITIZERS = {
    'sanitize', 'escapeHtml', 'escapeHTML', 'sanitizeHtml',
    'sanitizeHTML', 'htmlspecialchars', 'escape', 'encodeURI',
    'encodeURIComponent', 'DOMPurify.sanitize',
    'filterXSS', 'xssFilters.inHTMLData',
    'xssFilters.inSingleQuotedAttr', 'xssFilters.inDoubleQuotedAttr',
    'he.encode', 'entities.encode'
}

class XSSRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="Cross-Site Scripting (XSS)",
            cwe_id="CWE-79",
            description="User input used in innerHTML or document.write() without proper sanitization."
        )

    def detect(self, ast, file_path, code_lines):
        vulns = []
        self._walk(ast, file_path, code_lines, vulns, parent_type=None,
                   tainted_vars=set(), taint_depth=0)
        return vulns

    def _walk(self, node, file_path, code_lines, vulns, parent_type, tainted_vars, taint_depth):
        if not isinstance(node, dict):
            return tainted_vars, taint_depth

        node_type = node.get('type')
        new_tainted = set(tainted_vars)
        new_depth = taint_depth

        # ---------- Taint propagation ----------
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

        # ---------- innerHTML assignment ----------
        if node_type == 'AssignmentExpression':
            left = node.get('left')
            right = node.get('right')
            if left and left.get('type') == 'MemberExpression':
                prop = left.get('property')
                if isinstance(prop, dict) and prop.get('name') == 'innerHTML':
                    if right and self._references_tainted_var(right, new_tainted):
                        sanitized = self._is_sanitized_expression(right, new_tainted, XSS_SANITIZERS)
                        if sanitized:
                            score = 50 if new_depth == 1 else 40
                        else:
                            score = 90 if new_depth == 1 else 70
                        if score >= 50:
                            line = node['loc']['start']['line']
                            snippet = code_lines[line-1].strip() if line-1 < len(code_lines) else ''
                            obj = left.get('object')
                            obj_name = obj.get('name', 'an element') if isinstance(obj, dict) else 'an element'
                            desc = f"User-controlled input assigned to {obj_name}.innerHTML."
                            remed = f"Use {obj_name}.textContent or sanitize the input."
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

        # ---------- document.write() ----------
        if node_type == 'CallExpression':
            callee = node.get('callee')
            if callee and callee.get('type') == 'MemberExpression':
                obj = callee.get('object')
                prop = callee.get('property')
                if obj and prop and obj.get('name') == 'document' and prop.get('name') == 'write':
                    args = node.get('arguments', [])
                    if args and self._references_tainted_var(args[0], new_tainted):
                        sanitized = self._is_sanitized_expression(args[0], new_tainted, XSS_SANITIZERS)
                        score = 50 if sanitized else (90 if new_depth == 1 else 70)
                        if score >= 50:
                            line = node['loc']['start']['line']
                            snippet = code_lines[line-1].strip() if line-1 < len(code_lines) else ''
                            desc = "document.write() with user-controlled content."
                            remed = "Avoid document.write(). Use safe DOM methods."
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

            # ---------- React dangerouslySetInnerHTML ----------
            if callee and self._is_react_create_element(callee):
                args = node.get('arguments', [])
                if len(args) >= 2:
                    props = args[1]
                    if isinstance(props, dict) and props.get('type') == 'ObjectExpression':
                        for prop_node in props.get('properties', []):
                            key = prop_node.get('key')
                            if key and key.get('name') == 'dangerouslySetInnerHTML':
                                value = prop_node.get('value')
                                if value and value.get('type') == 'ObjectExpression':
                                    for inner_prop in value.get('properties', []):
                                        inner_key = inner_prop.get('key')
                                        if inner_key and inner_key.get('name') == '__html':
                                            inner_value = inner_prop.get('value')
                                            if inner_value and self._references_tainted_var(inner_value, new_tainted):
                                                line = node['loc']['start']['line']
                                                snippet = code_lines[line-1].strip() if line-1 < len(code_lines) else ''
                                                desc = "User-controlled input passed to dangerouslySetInnerHTML."
                                                remed = "Avoid dangerouslySetInnerHTML with user input. Sanitize or use safe alternatives."
                                                vulns.append(Vulnerability(
                                                    vuln_type=self.vuln_type,
                                                    cwe_id=self.cwe_id,
                                                    file_path=file_path,
                                                    line_number=line,
                                                    code_snippet=snippet,
                                                    description=desc,
                                                    remediation=remed,
                                                    confidence_score=90
                                                ))

        # Recurse
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

    # ---------- helpers ----------
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

    def _is_sanitized_expression(self, expr, tainted_vars, sanitizers):
        if isinstance(expr, dict) and expr.get('type') == 'CallExpression':
            callee = expr.get('callee')
            if callee:
                func_name = self._get_full_name(callee)
                if func_name in sanitizers:
                    return True
        return False

    def _is_react_create_element(self, callee):
        if callee and callee.get('type') == 'MemberExpression':
            obj = callee.get('object')
            prop = callee.get('property')
            if obj and obj.get('name') == 'React' and prop and prop.get('name') == 'createElement':
                return True
        return False

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