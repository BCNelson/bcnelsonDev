/**
 * Argument parser for terminal commands.
 * Supports --long-flags, -s short flags, and --key=value options.
 */

export interface ParsedArgs {
  /** Non-flag arguments in order */
  positional: string[];
  /** Boolean flags: -v, --verbose, -h, --help */
  flags: Set<string>;
  /** Value options: --file=x, -f x */
  options: Map<string, string>;
}

export interface ArgSpec {
  /** Internal name for this argument */
  name: string;
  /** Short flag: -h */
  short?: string;
  /** Long flag: --help */
  long?: string;
  /** Whether this flag expects a value */
  hasValue?: boolean;
  /** Description for help text */
  description: string;
}

/**
 * Parse command arguments according to specification.
 *
 * @param args - Arguments to parse (excluding command name)
 * @param spec - Argument specification
 * @returns Parsed arguments
 */
export function parseArgs(args: string[], spec: ArgSpec[]): ParsedArgs {
  const result: ParsedArgs = {
    positional: [],
    flags: new Set(),
    options: new Map(),
  };

  // Build lookup maps
  const shortToName = new Map<string, string>();
  const longToName = new Map<string, string>();
  const hasValue = new Set<string>();

  for (const s of spec) {
    if (s.short) shortToName.set(s.short, s.name);
    if (s.long) longToName.set(s.long, s.name);
    if (s.hasValue) hasValue.set(s.name);
  }

  let i = 0;
  while (i < args.length) {
    const arg = args[i];

    if (arg === "--") {
      // Everything after -- is positional
      result.positional.push(...args.slice(i + 1));
      break;
    } else if (arg.startsWith("--")) {
      // Long option
      const eqIndex = arg.indexOf("=");
      if (eqIndex !== -1) {
        // --key=value format
        const key = arg.slice(2, eqIndex);
        const value = arg.slice(eqIndex + 1);
        const name = longToName.get(key) ?? key;
        result.options.set(name, value);
      } else {
        // --flag or --key value
        const key = arg.slice(2);
        const name = longToName.get(key) ?? key;
        if (hasValue.has(name) && i + 1 < args.length) {
          result.options.set(name, args[i + 1]);
          i++;
        } else {
          result.flags.add(name);
        }
      }
    } else if (arg.startsWith("-") && arg.length > 1) {
      // Short option(s)
      const chars = arg.slice(1);
      for (let j = 0; j < chars.length; j++) {
        const char = chars[j];
        const name = shortToName.get(char) ?? char;
        if (hasValue.has(name)) {
          // Value follows: either rest of this arg or next arg
          if (j + 1 < chars.length) {
            result.options.set(name, chars.slice(j + 1));
            break;
          } else if (i + 1 < args.length) {
            result.options.set(name, args[i + 1]);
            i++;
            break;
          }
        } else {
          result.flags.add(name);
        }
      }
    } else {
      // Positional argument
      result.positional.push(arg);
    }
    i++;
  }

  return result;
}

/**
 * Format help text for a command.
 *
 * @param command - Command name
 * @param description - Command description
 * @param spec - Argument specification
 * @param usage - Optional usage pattern
 * @returns Formatted help string
 */
export function formatHelp(
  command: string,
  description: string,
  spec: ArgSpec[],
  usage?: string
): string {
  const lines: string[] = [];

  // Usage line
  if (usage) {
    lines.push(`Usage: ${command} ${usage}`);
  } else {
    lines.push(`Usage: ${command} [options]`);
  }
  lines.push("");

  // Description
  lines.push(description);
  lines.push("");

  // Options
  if (spec.length > 0) {
    lines.push("Options:");
    for (const s of spec) {
      const flags: string[] = [];
      if (s.short) flags.push(`-${s.short}`);
      if (s.long) flags.push(`--${s.long}`);
      const flagStr = flags.join(", ");
      lines.push(`  ${flagStr.padEnd(20)} ${s.description}`);
    }
  }

  return lines.join("\n");
}
