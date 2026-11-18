import * as walk from 'acorn-walk';
import type * as acorn from 'acorn';
import {
  type RuleContext,
  type RuleFinding,
  getCalleeName,
  getLineSnippet,
} from './shared';

export function runInsecureEvalRule(ctx: RuleContext): RuleFinding[] {
  const findings: RuleFinding[] = [];
  const seenLines = new Set<number>();

  const record = (localLine: number, column: number, detail: string) => {
    const absLine = ctx.startLine + localLine - 1;
    if (seenLines.has(absLine)) return;
    seenLines.add(absLine);
    findings.push({
      type: 'Insecure eval()',
      cweId: 'CWE-95',
      line: absLine,
      column,
      snippet: getLineSnippet(ctx.lines, localLine),
      detail,
    });
  };

  if (ctx.ast) {
    walk.simple(ctx.ast, {
      CallExpression(node) {
        const call = node as acorn.CallExpression;
        const calleeName = getCalleeName(call.callee);
        if (!calleeName) return;

        if (calleeName === 'eval' || calleeName === 'window.eval' || calleeName === 'global.eval') {
          const loc = call.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            `Direct invocation of ${calleeName}() evaluates arbitrary code strings.`
          );
          return;
        }

        if (calleeName === 'Function') {
          const loc = call.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            'Invocation of Function() dynamically compiles strings as executable code.'
          );
          return;
        }

        if (
          calleeName === 'setTimeout' ||
          calleeName === 'setInterval' ||
          calleeName === 'window.setTimeout' ||
          calleeName === 'window.setInterval'
        ) {
          const firstArg = call.arguments[0];
          if (
            firstArg &&
            ((firstArg.type === 'Literal' && typeof firstArg.value === 'string') ||
              firstArg.type === 'TemplateLiteral' ||
              firstArg.type === 'BinaryExpression')
          ) {
            const loc = call.loc?.start ?? { line: 1, column: 0 };
            record(
              loc.line,
              loc.column + 1,
              `String-based code passed to ${calleeName}() causes implicit eval().`
            );
          }
        }
      },
      NewExpression(node) {
        const expr = node as acorn.NewExpression;
        if (expr.callee.type === 'Identifier' && expr.callee.name === 'Function') {
          const loc = expr.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            'new Function() dynamically compiles strings as executable JavaScript.'
          );
        }
      },
    });
  }

  if (!ctx.ast) {
    ctx.lines.forEach((lineText, idx) => {
      if (/\beval\s*\(/.test(lineText) || /\bnew\s+Function\s*\(/.test(lineText)) {
        record(idx + 1, 1, 'Insecure dynamic code evaluation detected.');
      }
    });
  }

  return findings;
}
