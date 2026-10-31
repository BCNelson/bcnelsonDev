/**
 * Username and email normalization/validation (design §5). The normalized
 * forms are what UserIndex stores and looks up.
 */

import { config } from './config';

/** RFC 5321 limits; protocol constants rather than policy. */
const EMAIL_MAX_LENGTH = 254;
const EMAIL_LOCAL_MAX_LENGTH = 64;

const NON_ASCII = /[^\x20-\x7e]/;

export type UsernameError = 'empty' | 'non_ascii' | 'invalid_format' | 'reserved';
export type EmailError = 'empty' | 'too_long' | 'invalid_format';

export type Validation<E> =
  | { ok: true; norm: string; display: string }
  | { ok: false; reason: E };

/**
 * Trim and lowercase ASCII letters only, so look-alikes such as the Kelvin
 * sign never fold into an ASCII handle.
 */
export function normalizeUsername(input: string): string {
  return input.trim().replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/** Validate a username as typed; `display` keeps the user's casing. */
export function validateUsername(input: string): Validation<UsernameError> {
  const display = input.trim();
  if (display === '') return { ok: false, reason: 'empty' };
  if (NON_ASCII.test(display)) return { ok: false, reason: 'non_ascii' };
  const norm = normalizeUsername(display);
  if (config.RESERVED_USERNAMES.includes(norm) || config.SUBDOMAIN_NAMES.includes(norm)) {
    return { ok: false, reason: 'reserved' };
  }
  if (!config.USERNAME_PATTERN.test(norm)) return { ok: false, reason: 'invalid_format' };
  return { ok: true, norm, display };
}

/** Trim and lowercase. No Gmail dot or +tag stripping. */
export function normalizeEmail(input: string): string {
  return input.trim().toLowerCase();
}

/**
 * Pragmatic email check: one `@`, a non-empty local part, a dotted domain
 * with sane labels, no whitespace or control characters. Delivery of the
 * verification code is the real test.
 */
export function validateEmail(input: string): Validation<EmailError> {
  const display = input.trim();
  if (display === '') return { ok: false, reason: 'empty' };
  if (display.length > EMAIL_MAX_LENGTH) return { ok: false, reason: 'too_long' };
  const norm = normalizeEmail(display);
  if (/[\s\x00-\x1f\x7f]/.test(norm)) return { ok: false, reason: 'invalid_format' };
  const at = norm.lastIndexOf('@');
  if (at <= 0 || norm.indexOf('@') !== at) return { ok: false, reason: 'invalid_format' };
  const local = norm.slice(0, at);
  const domain = norm.slice(at + 1);
  if (local.length > EMAIL_LOCAL_MAX_LENGTH) return { ok: false, reason: 'invalid_format' };
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
    return { ok: false, reason: 'invalid_format' };
  }
  const labels = domain.split('.');
  if (labels.length < 2) return { ok: false, reason: 'invalid_format' };
  for (const label of labels) {
    if (label === '' || label.startsWith('-') || label.endsWith('-')) {
      return { ok: false, reason: 'invalid_format' };
    }
    if (/[^\p{L}\p{N}-]/u.test(label)) return { ok: false, reason: 'invalid_format' };
  }
  return { ok: true, norm, display };
}

export type IdentifierKind = 'email' | 'username';

/** Login identifier: contains `@` → email, otherwise username. */
export function classifyIdentifier(input: string): { kind: IdentifierKind; norm: string } {
  return input.includes('@')
    ? { kind: 'email', norm: normalizeEmail(input) }
    : { kind: 'username', norm: normalizeUsername(input) };
}
