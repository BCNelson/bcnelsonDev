import { describe, expect, it } from 'vitest';
import { config } from '../../src/config';
import { validateUsername } from '../../src/identifiers';

describe('reserved subdomain usernames', () => {
  it('lists the expected subdomain names', () => {
    for (const name of ['auth', 'www', 'api', 'example', 'mail', 'profile', 'admin', 'status', 'blog', 'dev',
      'staging', 'test', 'app', 'cdn', 'static', 'assets']) {
      expect(config.SUBDOMAIN_NAMES).toContain(name);
    }
  });

  it('rejects every subdomain name in any case', () => {
    for (const name of config.SUBDOMAIN_NAMES) {
      expect(validateUsername(name)).toEqual({ ok: false, reason: 'reserved' });
      expect(validateUsername(name.toUpperCase())).toEqual({ ok: false, reason: 'reserved' });
    }
  });

  it('still allows names that merely contain one', () => {
    expect(validateUsername('blogger')).toMatchObject({ ok: true, norm: 'blogger' });
    expect(validateUsername('test-user')).toMatchObject({ ok: true });
  });
});
