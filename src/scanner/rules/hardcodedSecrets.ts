import * as walk from 'acorn-walk';
import type * as acorn from 'acorn';
import { type RuleContext, type RuleFinding, getLineSnippet } from './shared';

const SECRET_IDENTIFIER_PATTERN =
  /^(api_?key|apikey|secret|secret_?key|client_?secret|access_?token|auth_?token|jwt_?secret|private_?key|password|passwd|pwd|db_?password|aws_?secret_?access_?key|stripe_?key|github_?token)$/i;

const SECRET_VALUE_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: 'AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { label: 'GitHub Personal Access Token', regex: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/ },
  { label: 'Stripe Secret Key', regex: /\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b/ },
  { label: 'Google API Key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { label: 'Private Key Block', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { label: 'Slack Token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { label: 'Embedded DB Credentials URI', regex: /\b(?:mongodb|postgres|postgresql|mysql|redis):\/\/[^:\s]+:[^@\s]+@/i },
];

const PLACEHOLDER_VALUES = new Set([
  '',
  'changeme',
  'your-api-key',
  'your_api_key',
  'your-secret-key',
  'your-secret-key-change-in-production',
  'placeholder',
  'example',
  'test',
  'dummy',
  'none',
  'null',
  'undefined',
]);

function looksLikeRealSecretLiteral(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 6) return false;
  if (PLACEHOLDER_VALUES.has(trimmed.toLowerCase())) return false;
  if (/^(process\.env|import\.meta\.env|\$\{|<\?php)/i.test(trimmed)) return false;
  return true;
}

export function runHardcodedSecretsRule(ctx: RuleContext): RuleFinding[] {
  const findings: RuleFinding[] = [];
  const seenLines = new Set<number>();

  const record = (localLine: number, column: number, detail: string) => {
    const absLine = ctx.startLine + localLine - 1;
    if (seenLines.has(absLine)) return;
    seenLines.add(absLine);
    findings.push({
      type: 'Hardcoded Secrets',
      cweId: 'CWE-798',
      line: absLine,
      column,
      snippet: getLineSnippet(ctx.lines, localLine),
      detail,
    });
  };

  if (ctx.ast) {
    walk.simple(ctx.ast, {
      VariableDeclarator(node) {
        const decl = node as acorn.VariableDeclarator;
        if (
          decl.id.type === 'Identifier' &&
          SECRET_IDENTIFIER_PATTERN.test(decl.id.name) &&
          decl.init?.type === 'Literal' &&
          typeof decl.init.value === 'string' &&
          looksLikeRealSecretLiteral(decl.init.value)
        ) {
          const loc = decl.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            `Hardcoded credential assigned to variable '${decl.id.name}'.`
          );
        }
      },
      Property(node) {
        const prop = node as acorn.Property;
        const keyName =
          prop.key.type === 'Identifier'
            ? prop.key.name
            : prop.key.type === 'Literal' && typeof prop.key.value === 'string'
            ? prop.key.value
            : null;
        if (
          keyName &&
          SECRET_IDENTIFIER_PATTERN.test(keyName) &&
          prop.value.type === 'Literal' &&
          typeof prop.value.value === 'string' &&
          looksLikeRealSecretLiteral(prop.value.value)
        ) {
          const loc = prop.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            `Hardcoded credential stored in object property '${keyName}'.`
          );
        }
      },
      AssignmentExpression(node) {
        const assign = node as acorn.AssignmentExpression;
        let name: string | null = null;
        if (assign.left.type === 'Identifier') {
          name = assign.left.name;
        } else if (
          assign.left.type === 'MemberExpression' &&
          !assign.left.computed &&
          assign.left.property.type === 'Identifier'
        ) {
          name = assign.left.property.name;
        }

        if (
          name &&
          SECRET_IDENTIFIER_PATTERN.test(name) &&
          assign.right.type === 'Literal' &&
          typeof assign.right.value === 'string' &&
          looksLikeRealSecretLiteral(assign.right.value)
        ) {
          const loc = assign.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            `Hardcoded credential assigned to '${name}'.`
          );
        }
      },
      Literal(node) {
        const lit = node as acorn.Literal;
        if (typeof lit.value !== 'string') return;
        for (const pattern of SECRET_VALUE_PATTERNS) {
          if (pattern.regex.test(lit.value)) {
            const loc = lit.loc?.start ?? { line: 1, column: 0 };
            record(loc.line, loc.column + 1, `Detected ${pattern.label} literal in source.`);
            break;
          }
        }
      },
    });
  }

  // Fallback pattern check for token formats and fallback mode
  ctx.lines.forEach((lineText, idx) => {
    for (const pattern of SECRET_VALUE_PATTERNS) {
      if (pattern.regex.test(lineText)) {
        record(idx + 1, 1, `Detected ${pattern.label} pattern in source.`);
        break;
      }
    }
    if (!ctx.ast) {
      const assignMatch = lineText.match(
        /\b(api_?key|secret_?key|password|passwd|auth_?token|access_?token)\b\s*[:=]\s*['"]([^'"]{6,})['"]/i
      );
      if (assignMatch && looksLikeRealSecretLiteral(assignMatch[2])) {
        record(idx + 1, 1, `Hardcoded credential assigned to '${assignMatch[1]}'.`);
      }
    }
  });

  return findings;
}
