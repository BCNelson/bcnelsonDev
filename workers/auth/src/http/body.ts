/**
 * Request bodies for auth POSTs: JSON or form-encoded, read the same way.
 */

import { config } from '../config';
import type { AppContext } from './index';

export interface RequestBody {
  /** Top-level string fields, each at most MAX_FIELD_LENGTH. */
  fields: Record<string, string>;
  /** The parsed JSON object (for nested values, e.g. WebAuthn responses); null for forms. */
  json: Record<string, unknown> | null;
}

const FORM_TYPES = ['application/x-www-form-urlencoded', 'multipart/form-data'];

function contentType(c: AppContext): string {
  return (c.req.header('Content-Type') ?? '').split(';')[0]!.trim().toLowerCase();
}

/** True for a form post (no JS) that didn't ask for JSON: answer with redirects, not JSON. */
export function isFormPost(c: AppContext): boolean {
  if (!FORM_TYPES.includes(contentType(c))) return false;
  return !(c.req.header('Accept') ?? '').includes('application/json');
}

/** Parses the body; null when it is malformed, of another type, or has an over-long field. */
export async function readBody(c: AppContext): Promise<RequestBody | null> {
  const type = contentType(c);
  let raw: Record<string, unknown>;
  let json: Record<string, unknown> | null = null;
  try {
    if (type === 'application/json') {
      const parsed: unknown = await c.req.json();
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
      raw = json = parsed as Record<string, unknown>;
    } else if (FORM_TYPES.includes(type)) {
      raw = await c.req.parseBody();
    } else {
      return null;
    }
  } catch {
    return null;
  }
  const fields: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value !== 'string') continue;
    if (value.length > config.MAX_FIELD_LENGTH) return null;
    fields[key] = value;
  }
  return { fields, json };
}
