 # scanner/rules/sql_injection.py
import re
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

USER_INPUT_SOURCES = {
    'location.search', 'location.hash', 'location.href',
    'document.cookie', 'document.referrer',
    'window.name',
    'req.query', 'req.params', 'req.body', 'req.cookies',
    'request.url', 'request.args', 'request.json',
}

SQL_SANITIZERS = {
    'escape', 'mysql.escape', 'pg.escape', 'sqlite.escape',
    'quote', 'param', 'escapeSQL', 'sanitizeSQL',
    'db.escape', 'connection.escape', 'pool.escape',
    'sqlstring.escape', 'sqlstring.format'
}

class SQLInjectionRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="SQL Injection",
            cwe_id="CWE-89",
            description="User input concatenated into SQL query."
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

        # Taint propagation
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

        # SQL concatenation detection
        if node_type == 'BinaryExpression' and node.get('operator') == '+':
            if parent_type != 'ReturnStatement':
                left = node.get('left')
                right = node.get('right')
                if self._contains_sql(left) or self._contains_sql(right):
                    if self._references_tainted_var(left, new_tainted) or \
                       self._references_tainted_var(right, new_tainted):
                        tainted_side = left if self._references_tainted_var(left, new_tainted) else right
                        sanitized = self._is_sanitized_expression(tainted_side, new_tainted, SQL_SANITIZERS)
                        score = 50 if sanitized else (90 if new_depth == 1 else 70)
                        if score >= 50:
                            line = node['loc']['start']['line']
                            snippet = code_lines[line-1].strip() if line-1 < len(code_lines) else ''
                            vars_used = self._extract_identifiers(left) + self._extract_identifiers(right)
                            sql_part = self._get_sql_string(left) or self._get_sql_string(right)
                            var_names = ', '.join(set(vars_used))
                            desc = f"SQL query built by concatenating {var_names}."
                            if sql_part:
                                desc += f" The string contains '{sql_part[:60]}...'"
                            remed = f"Use parameterized queries. Replace concatenation for {var_names} with placeholders."
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

    # ----- helpers (unchanged from earlier) -----
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

    def _contains_sql(self, node):
        if isinstance(node, dict) and node.get('type') == 'Literal':
            val = node.get('value', '')
            if isinstance(val, str):
                pattern = r'\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b'
                if re.search(pattern, val, re.IGNORECASE):
                    if re.search(r'dropdown', val, re.IGNORECASE):
                        return False
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

    def _get_sql_string(self, node):
        if isinstance(node, dict):
            if node.get('type') == 'Literal' and isinstance(node.get('value'), str):
                val = node['value']
                if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b', val, re.IGNORECASE) \
                   and not re.search(r'dropdown', val, re.IGNORECASE):
                    return val
            for value in node.values():
                result = self._get_sql_string(value)
                if result:
                    return result
        elif isinstance(node, list):
            for item in node:
                result = self._get_sql_string(item)
                if result:
                    return result
        return None

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