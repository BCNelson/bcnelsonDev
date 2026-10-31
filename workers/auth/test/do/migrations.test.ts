import { describe, expect, it } from 'vitest';
import { runMigrations } from '../../src/do/migrations';
import { USER_INDEX_MIGRATIONS, USER_MIGRATIONS } from '../../src/do/schema';
import { fakeState } from './fake-storage';

function storage() {
  const { state } = fakeState();
  return state.storage as unknown as Parameters<typeof runMigrations>[0];
}

function tables(s: ReturnType<typeof storage>): string[] {
  return s.sql.exec<{ name: string }>(
    "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
  ).toArray().map((r) => r.name);
}

describe('runMigrations', () => {
  it('applies each migration once, in order', () => {
    const s = storage();
    expect(runMigrations(s, ['CREATE TABLE a (x)', 'CREATE TABLE b (y)'])).toEqual([1, 2]);
    expect(runMigrations(s, ['CREATE TABLE a (x)', 'CREATE TABLE b (y)'])).toEqual([]);
    expect(runMigrations(s, ['CREATE TABLE a (x)', 'CREATE TABLE b (y)', (sql) => {
      sql.exec('CREATE TABLE c (z)');
    }])).toEqual([3]);
    expect(tables(s)).toEqual(['_migrations', 'a', 'b', 'c']);
  });

  it('rolls back a failing migration and leaves it unrecorded', () => {
    const s = storage();
    expect(() => runMigrations(s, ['CREATE TABLE a (x); CREATE TABLE a (x)'])).toThrow();
    expect(tables(s)).toEqual(['_migrations']);
    expect(runMigrations(s, ['CREATE TABLE a (x)'])).toEqual([1]);
  });

  it('creates the design §4 schemas', () => {
    const index = storage();
    runMigrations(index, USER_INDEX_MIGRATIONS);
    expect(tables(index)).toEqual(
      ['_migrations', 'challenges', 'emails', 'handles', 'identities', 'oauth_clients', 'oauth_pending', 'pending_signups', 'send_limits', 'users'],
    );
    const user = storage();
    runMigrations(user, USER_MIGRATIONS);
    expect(tables(user)).toEqual([
      '_migrations', 'action_limits', 'audit_log', 'credentials', 'emails', 'login_attempts',
      'maintenance', 'oauth_codes', 'oauth_grants', 'oauth_requests', 'oauth_tokens', 'passkey_ids',
      'pending_emails', 'profile', 'sessions', 'tokens',
    ]);
  });

  it('enforces the handles status check', () => {
    const s = storage();
    runMigrations(s, USER_INDEX_MIGRATIONS);
    expect(() => s.sql.exec(
      "INSERT INTO handles (username_norm, status) VALUES ('x', 'bogus')",
    )).toThrow();
  });
});
