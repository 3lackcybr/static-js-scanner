import * as walk from 'acorn-walk';
import type * as acorn from 'acorn';
import {
  type RuleContext,
  type RuleFinding,
  containsDynamicConcat,
  extractRawText,
  getCalleeName,
  getLineSnippet,
  isStaticLiteral,
} from './shared';

const SQL_KEYWORD_PATTERN =
  /\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|EXEC\s+)/i;

const SQL_EXEC_METHODS = new Set([
  'query',
  'execute',
  'exec',
  'raw',
  'prepare',
  'all',
  'get',
  'run',
]);

export function runSqlInjectionRule(ctx: RuleContext): RuleFinding[] {
  const findings: RuleFinding[] = [];
  const seenLines = new Set<number>();

  const record = (localLine: number, column: number, detail: string) => {
    const absLine = ctx.startLine + localLine - 1;
    if (seenLines.has(absLine)) return;
    seenLines.add(absLine);
    findings.push({
      type: 'SQL Injection',
      cweId: 'CWE-89',
      line: absLine,
      column,
      snippet: getLineSnippet(ctx.lines, localLine),
      detail,
    });
  };

  if (ctx.ast) {
    walk.simple(ctx.ast, {
      BinaryExpression(node) {
        const bin = node as acorn.BinaryExpression;
        if (bin.operator !== '+') return;
        const raw = extractRawText(ctx.code, bin);
        if (SQL_KEYWORD_PATTERN.test(raw) && containsDynamicConcat(bin)) {
          const loc = bin.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            'SQL statement built via string concatenation with dynamic expression.'
          );
        }
      },
      TemplateLiteral(node) {
        const tpl = node as acorn.TemplateLiteral;
        if (tpl.expressions.length === 0) return;
        const raw = extractRawText(ctx.code, tpl);
        if (SQL_KEYWORD_PATTERN.test(raw)) {
          const loc = tpl.loc?.start ?? { line: 1, column: 0 };
          record(
            loc.line,
            loc.column + 1,
            'SQL statement constructed with unparameterized template literal interpolation.'
          );
        }
      },
      CallExpression(node) {
        const call = node as acorn.CallExpression;
        const calleeName = getCalleeName(call.callee);
        if (!calleeName) return;
        const method = calleeName.split('.').pop() || '';
        if (!SQL_EXEC_METHODS.has(method)) return;
        const firstArg = call.arguments[0];
        if (!firstArg || firstArg.type === 'SpreadElement') return;

        if (containsDynamicConcat(firstArg)) {
          const raw = extractRawText(ctx.code, firstArg);
          if (SQL_KEYWORD_PATTERN.test(raw) || method === 'query' || method === 'execute') {
            const loc = call.loc?.start ?? { line: 1, column: 0 };
            record(
              loc.line,
              loc.column + 1,
              `Dynamic SQL expression passed directly to ${calleeName}().`
            );
          }
        } else if (!isStaticLiteral(firstArg) && firstArg.type === 'Identifier') {
          if (/sql|query/i.test(firstArg.name)) {
            const loc = call.loc?.start ?? { line: 1, column: 0 };
            record(
              loc.line,
              loc.column + 1,
              `Variable '${firstArg.name}' passed to ${calleeName}() without bound parameters.`
            );
          }
        }
      },
    });
  }

  // Fallback regex check when AST fails or for embedded snippets
  if (!ctx.ast) {
    ctx.lines.forEach((lineText, idx) => {
      if (
        SQL_KEYWORD_PATTERN.test(lineText) &&
        (/\$\{[^}]+\}/.test(lineText) || /['"`]\s*\+|\+\s*['"`]/.test(lineText))
      ) {
        record(
          idx + 1,
          1,
          'SQL query appears to concatenate or interpolate dynamic input.'
        );
      }
    });
  }

  return findings;
}
