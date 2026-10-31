/**
 * Social login provider registry. Add a provider: write an adapter
 * (see ./types.ts OAuthProvider), list it in PROVIDERS, add its
 * `<NAME>_CLIENT_ID` var and `<NAME>_CLIENT_SECRET` binding.
 */

import type { Env } from '../env';
import { github } from './github';
import { google } from './google';
import type { OAuthProvider } from './types';

export * from './types';

/** Every known provider, in button order. */
export const PROVIDERS: readonly OAuthProvider[] = [github, google];

/** The provider with this id if it exists and is enabled, else null. */
export function getProvider(env: Env, id: string): OAuthProvider | null {
  const provider = PROVIDERS.find((p) => p.id === id);
  return provider && provider.enabled(env) ? provider : null;
}

/** Enabled providers, in button order. */
export function enabledProviders(env: Env): OAuthProvider[] {
  return PROVIDERS.filter((p) => p.enabled(env));
}

/** Display label for a provider id (also for providers since disabled). */
export function providerLabel(id: string): string {
  return PROVIDERS.find((p) => p.id === id)?.label ?? id;
}
