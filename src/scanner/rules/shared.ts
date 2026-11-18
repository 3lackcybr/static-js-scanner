import type * as acorn from 'acorn';

export interface RuleFinding {
  type: string;
  cweId: string;
  line: number;
  column: number;
  snippet: string;
  detail?: string;
}

export interface RuleContext {
  code: string;
  lines: string[];
  ast: acorn.Program | null;
  startLine: number;
  sourceBlock: string;
}

export function getLineSnippet(lines: string[], localLine: number): string {
  const idx = Math.max(0, Math.min(lines.length - 1, localLine - 1));
  return (lines[idx] ?? '').trim().slice(0, 200);
}

export function getCalleeName(callee: acorn.Expression | acorn.Super): string | null {
  if (callee.type === 'Identifier') {
    return callee.name;
  }
  if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
    const obj = callee.object;
    if (obj.type === 'Identifier') {
      return `${obj.name}.${callee.property.name}`;
    }
    if (obj.type === 'MemberExpression' && !obj.computed && obj.property.type === 'Identifier') {
      return `${obj.property.name}.${callee.property.name}`;
    }
    return `.${callee.property.name}`;
  }
  return null;
}

export function getMemberPropertyName(node: acorn.MemberExpression): string | null {
  if (!node.computed && node.property.type === 'Identifier') {
    return node.property.name;
  }
  if (node.computed && node.property.type === 'Literal' && typeof node.property.value === 'string') {
    return node.property.value;
  }
  return null;
}

export function isStaticLiteral(node: acorn.Node | null | undefined): boolean {
  if (!node) return false;
  if (node.type === 'Literal') return true;
  if (node.type === 'TemplateLiteral') {
    return (node as acorn.TemplateLiteral).expressions.length === 0;
  }
  return false;
}

export function containsDynamicConcat(node: acorn.Node | null | undefined): boolean {
  if (!node) return false;
  if (node.type === 'TemplateLiteral') {
    return (node as acorn.TemplateLiteral).expressions.length > 0;
  }
  if (node.type === 'BinaryExpression') {
    const bin = node as acorn.BinaryExpression;
    if (bin.operator === '+') {
      return !isStaticLiteral(bin.left) || !isStaticLiteral(bin.right);
    }
  }
  return false;
}

export function extractRawText(code: string, node: acorn.Node): string {
  return code.slice(node.start, node.end);
}
