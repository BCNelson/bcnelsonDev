import { describe, expect, it, vi } from 'vitest';
import {
  createMailer, devMailer, emailServiceMailer, MailError, DEFAULT_FROM, DEFAULT_FROM_NAME,
} from '../src/email/mailer';
import * as t from '../src/email/templates';

const EVIL = '<script>alert("x")</script>&\'';

const all: [string, () => t.EmailContent][] = [
  ['signupCode', () => t.signupCode('123456', 15)],
  ['alreadyRegistered', () => t.alreadyRegistered('https://auth.bcnelson.dev/login', 'https://auth.bcnelson.dev/password/forgot')],
  ['addEmailCode', () => t.addEmailCode('654321', 15)],
  ['passwordReset', () => t.passwordReset('https://auth.bcnelson.dev/password/reset?token=abc', 30)],
  ['loginFailureAlert', () => t.loginFailureAlert(10)],
  ['emailAdded', () => t.emailAdded('new@example.com')],
  ['emailRemoved', () => t.emailRemoved('old@example.com')],
  ['primaryChanged', () => t.primaryChanged('primary@example.com')],
  ['passwordChanged', () => t.passwordChanged()],
];

describe('templates', () => {
  it.each(all)('%s returns subject, text and html', (_, make) => {
    const c = make();
    expect(c.subject).toBeTruthy();
    expect(c.text).toContain('bcnelson.dev');
    expect(c.html).toMatch(/^<!doctype html>/);
    expect(c.html).toContain('lang="en"');
    expect(c.html).not.toMatch(/<img|<script/i);
  });

  it('includes the code and expiry in both bodies', () => {
    for (const c of [t.signupCode('123456', 15), t.addEmailCode('123456', 15)]) {
      expect(c.text).toContain('123456');
      expect(c.html).toContain('123456');
      expect(c.text).toContain('15 minutes');
    }
    expect(t.signupCode('1', 1).text).toContain('1 minute.');
  });

  it('includes the urls in both bodies', () => {
    const reset = t.passwordReset('https://auth.bcnelson.dev/password/reset?token=a&b=1', 30);
    expect(reset.text).toContain('https://auth.bcnelson.dev/password/reset?token=a&b=1');
    expect(reset.html).toContain('href="https://auth.bcnelson.dev/password/reset?token=a&amp;b=1"');
    const ar = t.alreadyRegistered('https://l.example/login', 'https://l.example/reset');
    for (const body of [ar.text, ar.html]) {
      expect(body).toContain('https://l.example/login');
      expect(body).toContain('https://l.example/reset');
    }
  });

  it('includes addresses and counts', () => {
    expect(t.emailAdded('a@example.com').text).toContain('a@example.com');
    expect(t.emailRemoved('a@example.com').html).toContain('a@example.com');
    expect(t.primaryChanged('p@example.com').html).toContain('p@example.com');
    expect(t.loginFailureAlert(12).text).toContain('12 failed password attempts');
  });

  it('escapes interpolated values in html', () => {
    const cases = [
      t.signupCode(EVIL, 15),
      t.addEmailCode(EVIL, 15),
      t.alreadyRegistered(`https://x/"onmouseover="${EVIL}`, EVIL),
      t.passwordReset(`https://x/"><script>`, 30),
      t.emailAdded(EVIL),
      t.emailRemoved(EVIL),
      t.primaryChanged(EVIL),
    ];
    for (const c of cases) {
      expect(c.html).not.toContain('<script>');
      expect(c.html).not.toContain('"onmouseover="');
      expect(c.html).toContain('&lt;script&gt;');
    }
    // plain text carries the raw value
    expect(t.emailAdded(EVIL).text).toContain(EVIL);
  });

  it('escapeHtml covers the five special characters', () => {
    expect(t.escapeHtml(`<>&"'`)).toBe('&lt;&gt;&amp;&quot;&#39;');
  });
});

describe('mailer', () => {
  const msg = { to: 'u@example.com', subject: 'Hi', text: 'plain body', html: '<p>html</p>' };

  it('uses the dev mailer when the binding is absent', async () => {
    const log = vi.fn();
    await createMailer({}, { log }).send(msg);
    expect(log).toHaveBeenCalledOnce();
    const line = log.mock.calls[0]![0] as string;
    expect(line).toContain(`${DEFAULT_FROM_NAME} <${DEFAULT_FROM}>`);
    expect(line).toContain('To: u@example.com');
    expect(line).toContain('Subject: Hi');
    expect(line).toContain('plain body');
  });

  it('dev mailer defaults to console.log', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await devMailer().send(msg);
    expect(spy).toHaveBeenCalledOnce();
    spy.mockRestore();
  });

  it('sends through the binding with the default sender', async () => {
    const send = vi.fn(async () => ({ messageId: 'm1' }));
    await createMailer({ EMAIL: { send } as unknown as SendEmail }).send(msg);
    expect(send).toHaveBeenCalledWith({
      from: { email: 'no-reply@bcnelson.dev', name: 'bcnelson.dev' },
      to: 'u@example.com', subject: 'Hi', text: 'plain body', html: '<p>html</p>',
    });
  });

  it('honours a configured sender', async () => {
    const send = vi.fn(async () => ({ messageId: 'm1' }));
    await emailServiceMailer({ send } as unknown as SendEmail, { from: 'a@b.dev', fromName: 'B' }).send(msg);
    expect(send.mock.calls[0]).toEqual([expect.objectContaining({ from: { email: 'a@b.dev', name: 'B' } })]);
  });

  it('wraps binding errors with their code', async () => {
    const err = Object.assign(new Error('nope'), { code: 'E_SENDER_NOT_VERIFIED' });
    const send = vi.fn(async () => { throw err; });
    const p = emailServiceMailer({ send } as unknown as SendEmail).send(msg);
    await expect(p).rejects.toBeInstanceOf(MailError);
    await expect(p).rejects.toMatchObject({ code: 'E_SENDER_NOT_VERIFIED', cause: err });
  });
});
