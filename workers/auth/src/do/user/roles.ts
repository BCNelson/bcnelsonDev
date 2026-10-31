/**
 * Roles (design §8): `profile.roles`, a JSON array of values from config.ROLES.
 */

import { config } from '../../config';
import { parseStringArray } from '../sessions';
import { type UserContext, readProfile } from './context';

/** Add `role` if missing. Returns true when it was added. Throws for unknown roles. */
export function ensureRole(ctx: UserContext, role: string, reason: string): boolean {
  if (!config.ROLES.includes(role)) throw new Error(`Unknown role: ${role}`);
  const { sql } = ctx;
  return ctx.storage.transactionSync(() => {
    const profile = readProfile(sql);
    if (!profile) throw new Error('User profile does not exist');
    const roles = parseStringArray(profile.roles);
    if (roles.includes(role)) return false;
    sql.exec('UPDATE profile SET roles = ?', JSON.stringify([...roles, role]));
    ctx.audit('role.added', { role, reason });
    return true;
  });
}
