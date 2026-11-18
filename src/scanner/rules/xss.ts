import * as walk from 'acorn-walk';
import type * as acorn from 'acorn';
import {
  type RuleContext,
  type RuleFinding,
  getCalleeName,
  getLineSnippet,
  getMemberPropertyName,
  isStaticLiteral,
} from './shared';

const DANGEROUS_DOM_SINKS = new Set([
  'innerHTML',
  'outerHTML',
  'srcdoc',
]);

const DANGEROUS_CALL_SINKS = new Set([
  'document.write',
  'document.writeln',
  'insertAdjacentHTML',
  '.insertAdjacentHTML',
  '.html',
  '.append',
  '.prepend',
]);

export function runXssRule(ctx: RuleContext): RuleFinding[] {
  const findings: RuleFinding[] = [];
  const seenLines = new Set<number>();

  const record = (localLine: number, column: number, detail: string) => {
    const absLine = ctx.startLine + localLine - 1;
    if (seenLines.has(absLine)) return;
    seenLines.add(absLine);
    findings.push({
      type: 'Cross-Site Scripting (XSS)',
      cweId: 'CWE-79',
      line: absLine,
      column,
      snippet: getLineSnippet(ctx.lines, localLine),
      detail,
    });
  };

  if (ctx.ast) {
    walk.simple(ctx.ast, {
      AssignmentExpression(node) {
        const assign = node as acorn.AssignmentExpression;
        if (assign.left.type !== 'MemberExpression') return;
        const prop = getMemberPropertyName(assign.left);
        if (!prop) return;

        if (DANGEROUS_DOM_SINKS.has(prop) && !isStaticLiteral(assign.right)) {
          const loc = assign.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            `Dynamic value assigned to dangerous DOM sink '${prop}'.`
          );
          return;
        }

        if (
          (prop === 'href' || prop === 'src') &&
          assign.right.type === 'TemplateLiteral' &&
          assign.right.expressions.length > 0
        ) {
          const loc = assign.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            `Interpolated value assigned to '${prop}' without URL scheme validation.`
          );
        }
      },
      CallExpression(node) {
        const call = node as acorn.CallExpression;
        const calleeName = getCalleeName(call.callee);
        if (!calleeName) return;

        if (calleeName === 'document.write' || calleeName === 'document.writeln') {
          const arg = call.arguments[0];
          if (arg && !isStaticLiteral(arg)) {
            const loc = call.loc?.start ?? { line: 1, column: 0 };
            record(
              loc.line,
              loc.column + 1,
              `Untrusted or dynamic content written via ${calleeName}().`
            );
          }
          return;
        }

        const methodSuffix = calleeName.includes('.') ? `.${calleeName.split('.').pop()}` : calleeName;
        if (methodSuffix === '.insertAdjacentHTML') {
          const htmlArg = call.arguments[1];
          if (htmlArg && !isStaticLiteral(htmlArg)) {
            const loc = call.loc?.start ?? { line: 1, column: 0 };
            record(
              loc.line,
              loc.column + 1,
              `Dynamic HTML string passed to ${calleeName}().`
            );
          }
          return;
        }

        if (DANGEROUS_CALL_SINKS.has(methodSuffix)) {
          const arg = call.arguments[0];
          if (arg && !isStaticLiteral(arg) && (calleeName.startsWith('$') || calleeName.startsWith('jQuery') || methodSuffix === '.html')) {
            const loc = call.loc?.start ?? { line: 1, column: 0 };
            record(
              loc.line,
              loc.column + 1,
              `Dynamic HTML content passed to DOM manipulation method ${calleeName}().`
            );
          }
        }
      },
    });
  }

  if (!ctx.ast) {
    ctx.lines.forEach((lineText, idx) => {
      if (/\.(innerHTML|outerHTML)\s*=/.test(lineText) || /\bdocument\.write(ln)?\s*\(/.test(lineText)) {
        record(idx + 1, 1, 'Potential unsafe DOM sink usage detected.');
      }
    });
  }

  return findings;
}
