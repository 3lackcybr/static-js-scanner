import * as acorn from 'acorn';

export interface ParsedScript {
  ast: acorn.Program | null;
  parseWarning?: string;
}

export function parseJavaScript(code: string): ParsedScript {
  const trimmed = code.trim();
  if (!trimmed) {
    return { ast: null };
  }

  try {
    const ast = acorn.parse(code, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,
      allowHashBang: true,
      allowReturnOutsideFunction: true,
    });
    return { ast };
  } catch (moduleErr) {
    try {
      const ast = acorn.parse(code, {
        ecmaVersion: 'latest',
        sourceType: 'script',
        locations: true,
        allowHashBang: true,
        allowReturnOutsideFunction: true,
      });
      return { ast };
    } catch (scriptErr) {
      const message =
        scriptErr instanceof Error
          ? scriptErr.message
          : moduleErr instanceof Error
          ? moduleErr.message
          : 'Unable to parse JavaScript AST';
      return {
        ast: null,
        parseWarning: `AST parse fallback (${message}); pattern rules still applied.`,
      };
    }
  }
}
