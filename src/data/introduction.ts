import c from "ansi-colors";
c.enabled = true;

export const message = `
${c.cyan("╭──────────────────────────────────────────────────────────╮")}
${c.cyan("│")}  ${c.bold.white("Welcome to")} ${c.bold.cyanBright("bcnelson.dev")}                                 ${c.cyan("│")}
${c.cyan("│")}  ${c.gray("Backend Engineer | Infra Junkie")}                        ${c.cyan("│")}
${c.cyan("╰──────────────────────────────────────────────────────────╯")}

${c.gray("Type")} ${c.cyanBright("help")} ${c.gray("for available commands.")}
`;
