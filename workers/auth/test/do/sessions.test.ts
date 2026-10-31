import { describe, expect, it } from 'vitest';
import { config } from '../../src/config';
import {
  type SessionSecrets,
  buildClaims,
  decideRefresh,
  parseStringArray,
  rotatedSecrets,
} from '../../src/do/sessions';

const NOW = 1_800_000_000_000;

function row(overrides: Partial<SessionSecrets> = {}): SessionSecrets {
  return {
    secret_hash: 'current',
    prev_secret_hash: null,
    prev_valid_until: null,
    expires_at: NOW + config.REFRESH_TOKEN_TTL,
    revoked_at: null,
    ...overrides,
  };
}

describe('decideRefresh', () => {
  it('rejects unknown sessions', () => {
    expect(decideRefresh(null, 'x', NOW)).toEqual({ action: 'reject', reason: 'invalid' });
  });

  it('rotates on the current secret', () => {
    expect(decideRefresh(row(), 'current', NOW)).toEqual({ action: 'rotate' });
  });

  it('rejects a wrong secret as invalid', () => {
    expect(decideRefresh(row(), 'nope', NOW)).toEqual({ action: 'reject', reason: 'invalid' });
  });

  it('accepts the previous secret within the grace window', () => {
    const r = row({ prev_secret_hash: 'old', prev_valid_until: NOW + 1 });
    expect(decideRefresh(r, 'old', NOW)).toEqual({ action: 'grace' });
    expect(decideRefresh(r, 'old', NOW + 1)).toEqual({ action: 'grace' });
  });

  it('treats the previous secret after the grace window as reuse', () => {
    const r = row({ prev_secret_hash: 'old', prev_valid_until: NOW - 1 });
    expect(decideRefresh(r, 'old', NOW)).toEqual({ action: 'reuse' });
  });

  it('checks revoked before expired before secrets', () => {
    expect(decideRefresh(row({ revoked_at: NOW - 5 }), 'current', NOW))
      .toEqual({ action: 'reject', reason: 'revoked' });
    expect(decideRefresh(row({ expires_at: NOW }), 'current', NOW))
      .toEqual({ action: 'reject', reason: 'expired' });
  });
});

describe('rotatedSecrets', () => {
  it('keeps the old hash for REFRESH_GRACE and slides expiry', () => {
    expect(rotatedSecrets({ secret_hash: 'a' }, 'b', NOW)).toEqual({
      secret_hash: 'b',
      prev_secret_hash: 'a',
      prev_valid_until: NOW + config.REFRESH_GRACE,
      expires_at: NOW + config.REFRESH_TOKEN_TTL,
      last_seen_at: NOW,
    });
  });

  it('a rotate-then-grace sequence keeps both latest secrets usable', () => {
    // Tab A rotates a → b; tab B (still holding a) refreshes within grace → c.
    const afterA = { ...row({ secret_hash: 'a' }), ...rotatedSecrets({ secret_hash: 'a' }, 'b', NOW) };
    expect(decideRefresh(afterA, 'a', NOW + 10)).toEqual({ action: 'grace' });
    const afterB = { ...afterA, ...rotatedSecrets(afterA, 'c', NOW + 10) };
    expect(decideRefresh(afterB, 'c', NOW + 20)).toEqual({ action: 'rotate' });
    expect(decideRefresh(afterB, 'b', NOW + 20)).toEqual({ action: 'grace' });
    expect(decideRefresh(afterB, 'b', NOW + 10 + config.REFRESH_GRACE + 1)).toEqual({ action: 'reuse' });
  });
});

describe('buildClaims', () => {
  const profile = { user_id: 'usr_1', username: 'Brad', name: null, picture: null, roles: '[]' };
  const session = { id: 'ses_1', auth_time: 1_700_000_000_999, amr: '["pwd"]' };

  it('builds minimal claims with auth_time in seconds and no empty roles', () => {
    expect(buildClaims(profile, 'b@example.com', session)).toEqual({
      sub: 'usr_1',
      sid: 'ses_1',
      auth_time: 1_700_000_000,
      amr: ['pwd'],
      preferred_username: 'Brad',
      email: 'b@example.com',
    });
  });

  it('includes name, picture and roles when present', () => {
    const claims = buildClaims(
      { ...profile, name: 'Bradley', picture: 'https://x/p.png', roles: '["admin"]' },
      'b@example.com',
      session,
    );
    expect(claims).toMatchObject({ name: 'Bradley', picture: 'https://x/p.png', roles: ['admin'] });
  });
});

describe('parseStringArray', () => {
  it('tolerates bad JSON and non-strings', () => {
    expect(parseStringArray(null)).toEqual([]);
    expect(parseStringArray('{')).toEqual([]);
    expect(parseStringArray('{"a":1}')).toEqual([]);
    expect(parseStringArray('["a",1,"b"]')).toEqual(['a', 'b']);
  });
});
