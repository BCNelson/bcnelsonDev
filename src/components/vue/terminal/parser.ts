/**
 * Command tokenizer with support for quotes and escape sequences.
 *
 * Handles:
 * - Unquoted words: hello world -> ["hello", "world"]
 * - Double quotes: "hello world" -> ["hello world"]
 * - Single quotes: 'hello world' -> ["hello world"]
 * - Escapes in double quotes: "say \"hi\"" -> ["say \"hi\""]
 * - Backslash escapes: hello\ world -> ["hello world"]
 */
export function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let i = 0;

  while (i < input.length) {
    const char = input[i];

    if (char === '"') {
      // Double quoted string - interprets escapes
      i++;
      while (i < input.length && input[i] !== '"') {
        if (input[i] === "\\" && i + 1 < input.length) {
          const next = input[i + 1];
          if (next === '"' || next === "\\" || next === "n" || next === "t") {
            if (next === "n") {
              current += "\n";
            } else if (next === "t") {
              current += "\t";
            } else {
              current += next;
            }
            i += 2;
            continue;
          }
        }
        current += input[i];
        i++;
      }
      i++; // skip closing quote
    } else if (char === "'") {
      // Single quoted string - literal, no escape interpretation
      i++;
      while (i < input.length && input[i] !== "'") {
        current += input[i];
        i++;
      }
      i++; // skip closing quote
    } else if (char === "\\") {
      // Escape sequence outside quotes
      if (i + 1 < input.length) {
        current += input[i + 1];
        i += 2;
      } else {
        i++;
      }
    } else if (char === " " || char === "\t") {
      // Whitespace - end current token
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }
      i++;
    } else {
      // Regular character
      current += char;
      i++;
    }
  }

  // Push final token if exists
  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

/**
 * Find which token the cursor is currently in.
 * Returns { tokenIndex, offsetInToken } or null if cursor is in whitespace.
 */
export function findTokenAtCursor(
  input: string,
  cursorPosition: number
): { tokenIndex: number; offsetInToken: number; token: string } | null {
  const tokens = tokenize(input);
  if (tokens.length === 0) {
    return null;
  }

  // Walk through input to map positions to tokens
  let tokenIndex = 0;
  let tokenStart = 0;
  let i = 0;
  let inQuote: string | null = null;

  // Skip leading whitespace
  while (i < input.length && (input[i] === " " || input[i] === "\t")) {
    i++;
  }
  tokenStart = i;

  while (i < input.length && tokenIndex < tokens.length) {
    const char = input[i];

    if (inQuote) {
      if (char === inQuote && input[i - 1] !== "\\") {
        inQuote = null;
      }
      i++;
    } else if (char === '"' || char === "'") {
      inQuote = char;
      i++;
    } else if (char === "\\") {
      i += 2;
    } else if (char === " " || char === "\t") {
      // Check if cursor is in this token
      if (cursorPosition >= tokenStart && cursorPosition <= i) {
        return {
          tokenIndex,
          offsetInToken: cursorPosition - tokenStart,
          token: tokens[tokenIndex],
        };
      }
      tokenIndex++;
      // Skip whitespace to next token
      while (i < input.length && (input[i] === " " || input[i] === "\t")) {
        i++;
      }
      tokenStart = i;
    } else {
      i++;
    }
  }

  // Cursor might be in the last token
  if (cursorPosition >= tokenStart && tokenIndex < tokens.length) {
    return {
      tokenIndex,
      offsetInToken: cursorPosition - tokenStart,
      token: tokens[tokenIndex],
    };
  }

  // Cursor is at the end, after whitespace - implies new token
  if (cursorPosition >= input.length) {
    // If input ends with whitespace, we're starting a new token
    if (
      input.length > 0 &&
      (input[input.length - 1] === " " || input[input.length - 1] === "\t")
    ) {
      return {
        tokenIndex: tokens.length,
        offsetInToken: 0,
        token: "",
      };
    }
    // Otherwise we're at the end of the last token
    if (tokens.length > 0) {
      return {
        tokenIndex: tokens.length - 1,
        offsetInToken: tokens[tokens.length - 1].length,
        token: tokens[tokens.length - 1],
      };
    }
  }

  return null;
}
