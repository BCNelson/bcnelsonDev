/**
 * Email templates. Pure functions: each returns a subject plus complete
 * plain-text and HTML bodies. Every interpolated value is HTML-escaped.
 */

export interface EmailContent {
  subject: string;
  text: string;
  html: string;
}

const SITE = 'bcnelson.dev';

/** Escape a value for HTML text or a double-quoted attribute. */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Pre-escaped HTML fragment; produced only by the helpers below. */
interface Safe {
  __html: string;
}

const safe = (html: string): Safe => ({ __html: html });

/** Tagged template that escapes every interpolation unless it is already Safe. */
function h(strings: TemplateStringsArray, ...values: unknown[]): Safe {
  let out = strings[0] ?? '';
  values.forEach((v, i) => {
    const part = Array.isArray(v)
      ? v.map((x) => (isSafe(x) ? x.__html : escapeHtml(x))).join('')
      : isSafe(v) ? v.__html : escapeHtml(v);
    out += part + (strings[i + 1] ?? '');
  });
  return safe(out);
}

function isSafe(v: unknown): v is Safe {
  return typeof v === 'object' && v !== null && '__html' in v;
}

const P = 'margin:0 0 16px;font-size:16px;line-height:1.5;color:#1a1a1a;';
const SMALL = 'margin:24px 0 0;font-size:13px;line-height:1.5;color:#555555;';

const para = (content: unknown): Safe => h`<p style="${safe(P)}">${content}</p>`;

const codeBlock = (code: string): Safe =>
  h`<p style="${safe(P)}"><strong style="display:inline-block;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:28px;letter-spacing:6px;padding:8px 16px;background:#f2f2f2;border-radius:6px;color:#1a1a1a;">${code}</strong></p>`;

const button = (url: string, label: string): Safe =>
  h`<p style="${safe(P)}"><a href="${url}" style="display:inline-block;padding:10px 18px;background:#1a56db;color:#ffffff;text-decoration:underline;border-radius:6px;font-weight:bold;">${label}</a></p>
<p style="${safe(SMALL)}">If the button doesn't work, copy this address into your browser:<br><a href="${url}" style="color:#1a56db;word-break:break-all;">${url}</a></p>`;

const NOT_YOU = "If you didn't request this, you can ignore this email.";
const SECURITY = "If this wasn't you, reset your password and review your account's sign-in methods right away.";

/** Wrap body fragments in a minimal, accessible HTML document. */
function layout(subject: string, body: Safe[], footer: string): string {
  return h`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${subject}</title>
</head>
<body style="margin:0;padding:0;background:#ffffff;">
<div role="article" aria-label="${subject}" style="max-width:560px;margin:0 auto;padding:24px 16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<h1 style="margin:0 0 20px;font-size:20px;line-height:1.3;color:#1a1a1a;">${subject}</h1>
${body}
<p style="${safe(SMALL)}">${footer}</p>
<p style="${safe(SMALL)}">— ${SITE}</p>
</div>
</body>
</html>
`.__html;
}

/** Join plain-text paragraphs and add the signature. */
function textBody(...paragraphs: string[]): string {
  return [...paragraphs, `— ${SITE}`].join('\n\n') + '\n';
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/** Verification code for a new signup. */
export function signupCode(code: string, minutes: number): EmailContent {
  const subject = `Your ${SITE} verification code`;
  const expiry = `This code expires in ${plural(minutes, 'minute')}.`;
  return {
    subject,
    text: textBody(`Use this code to finish creating your ${SITE} account:`, code, expiry, NOT_YOU),
    html: layout(subject, [
      para(`Use this code to finish creating your ${SITE} account:`),
      codeBlock(code),
      para(expiry),
    ], NOT_YOU),
  };
}

/** Sent instead of a signup code when the address already has an account. */
export function alreadyRegistered(loginUrl: string, resetUrl: string): EmailContent {
  const subject = `You already have a ${SITE} account`;
  const intro = `Someone tried to sign up for ${SITE} with this email address, but it already belongs to an account.`;
  return {
    subject,
    text: textBody(
      intro,
      `Sign in: ${loginUrl}`,
      `Forgot your password? Reset it: ${resetUrl}`,
      "If this wasn't you, no action is needed; your account hasn't changed.",
    ),
    html: layout(subject, [
      para(intro),
      button(loginUrl, 'Sign in'),
      para(h`Forgot your password? <a href="${resetUrl}" style="color:#1a56db;">Reset it</a> (${resetUrl}).`),
    ], "If this wasn't you, no action is needed; your account hasn't changed."),
  };
}

/** Verification code for adding an address to an existing account. */
export function addEmailCode(code: string, minutes: number): EmailContent {
  const subject = `Confirm your new ${SITE} email address`;
  const expiry = `This code expires in ${plural(minutes, 'minute')}.`;
  return {
    subject,
    text: textBody(`Use this code to add this email address to your ${SITE} account:`, code, expiry, NOT_YOU),
    html: layout(subject, [
      para(`Use this code to add this email address to your ${SITE} account:`),
      codeBlock(code),
      para(expiry),
    ], NOT_YOU),
  };
}

/** Single-use password reset link. */
export function passwordReset(url: string, minutes: number): EmailContent {
  const subject = `Reset your ${SITE} password`;
  const intro = `We received a request to reset the password for your ${SITE} account.`;
  const expiry = `This link expires in ${plural(minutes, 'minute')} and can be used once.`;
  return {
    subject,
    text: textBody(intro, `Reset your password: ${url}`, expiry, `${NOT_YOU} Your password won't change.`),
    html: layout(subject, [para(intro), button(url, 'Reset password'), para(expiry)],
      `${NOT_YOU} Your password won't change.`),
  };
}

/** Alert after repeated failed password attempts. */
export function loginFailureAlert(count: number): EmailContent {
  const subject = `Failed sign-in attempts on your ${SITE} account`;
  const intro = `There were ${plural(count, 'failed password attempt')} on your ${SITE} account. Further attempts are being slowed down.`;
  const ok = 'If this was you, no action is needed.';
  return {
    subject,
    text: textBody(intro, ok, SECURITY),
    html: layout(subject, [para(intro), para(ok)], SECURITY),
  };
}

/** Alert that an address was added to the account. */
export function emailAdded(address: string): EmailContent {
  const subject = `An email address was added to your ${SITE} account`;
  return {
    subject,
    text: textBody(`The address ${address} was added to your ${SITE} account.`, SECURITY),
    html: layout(subject, [para(h`The address <strong>${address}</strong> was added to your ${SITE} account.`)], SECURITY),
  };
}

/** Alert that an address was removed from the account. */
export function emailRemoved(address: string): EmailContent {
  const subject = `An email address was removed from your ${SITE} account`;
  return {
    subject,
    text: textBody(`The address ${address} was removed from your ${SITE} account.`, SECURITY),
    html: layout(subject, [para(h`The address <strong>${address}</strong> was removed from your ${SITE} account.`)], SECURITY),
  };
}

/** Alert that the primary address changed. */
export function primaryChanged(newAddress: string): EmailContent {
  const subject = `Your ${SITE} primary email address changed`;
  return {
    subject,
    text: textBody(`The primary email address on your ${SITE} account is now ${newAddress}.`, SECURITY),
    html: layout(subject, [para(h`The primary email address on your ${SITE} account is now <strong>${newAddress}</strong>.`)], SECURITY),
  };
}

/** Alert that the password changed (including via reset). */
export function passwordChanged(): EmailContent {
  const subject = `Your ${SITE} password was changed`;
  const intro = `The password for your ${SITE} account was just changed.`;
  const help = "If this wasn't you, reset your password now and review your account's sign-in methods.";
  return {
    subject,
    text: textBody(intro, help),
    html: layout(subject, [para(intro)], help),
  };
}
