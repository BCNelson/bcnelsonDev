/** Rate limiting: binding wrappers plus pure per-user policies. */

export { checkIp, checkIdentifier } from './bindings';
export {
  type AttemptState,
  type BackoffDecision,
  EMPTY_ATTEMPTS,
  checkBackoff,
  lockoutDuration,
  recordFailure,
  recordSuccess,
} from './backoff';
export {
  type LimitedAction,
  type WindowDecision,
  actionLimit,
  checkActionLimit,
  slidingWindow,
} from './window';
