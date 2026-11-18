import * as walk from 'acorn-walk';
import type * as acorn from 'acorn';
import {
  type RuleContext,
  type RuleFinding,
  containsDynamicConcat,
  getCalleeName,
  getLineSnippet,
  isStaticLiteral,
} from './shared';

const EXEC_METHODS = new Set([
  'exec',
  'execSync',
  'spawn',
  'spawnSync',
  'execFile',
  'execFileSync',
]);

export function runCommandInjectionRule(ctx: RuleContext): RuleFinding[] {
  const findings: RuleFinding[] = [];
  const seenLines = new Set<number>();

  const record = (localLine: number, column: number, detail: string) => {
    const absLine = ctx.startLine + localLine - 1;
    if (seenLines.has(absLine)) return;
    seenLines.add(absLine);
    findings.push({
      type: 'Command Injection',
      cweId: 'CWE-78',
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

        const method = calleeName.split('.').pop() || '';
        if (!EXEC_METHODS.has(method)) return;

        // Avoid false positives for RegExp.prototype.exec when a regex literal is the object
        if (
          method === 'exec' &&
          call.callee.type === 'MemberExpression' &&
          call.callee.object.type === 'Literal'
        ) {
          return;
        }

        const firstArg = call.arguments[0];
        if (!firstArg || firstArg.type === 'SpreadElement') return;

        const isShellMethod = method === 'exec' || method === 'execSync';
        const hasShellOption =
          call.arguments.some(
            (arg) =>
              arg.type === 'ObjectExpression' &&
              arg.properties.some(
                (p) =>
                  p.type === 'Property' &&
                  p.key.type === 'Identifier' &&
                  p.key.name === 'shell' &&
                  p.value.type === 'Literal' &&
                  p.value.value === true
              )
          );

        if (isShellMethod && !isStaticLiteral(firstArg)) {
          const loc = call.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            `Dynamic command expression passed to shell execution function ${calleeName}().`
          );
          return;
        }

        if (containsDynamicConcat(firstArg) || (hasShellOption && !isStaticLiteral(firstArg))) {
          const loc = call.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            `Potentially unsanitized command or shell option passed to ${calleeName}().`
          );
        }
      },
    });
  }

  if (!ctx.ast) {
    ctx.lines.forEach((lineText, idx) => {
      if (/\b(exec|execSync|spawn|spawnSync)\s*\(/.test(lineText) && /\$\{|['"`]\s*\+/.test(lineText)) {
        record(idx + 1, 1, 'Dynamic string passed to OS command execution call.');
      }
    });
  }

  return findings;
}
