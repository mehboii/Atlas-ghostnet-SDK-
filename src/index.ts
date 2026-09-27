/**
 * @n11x/atlas — Atlas SDK for the GhostNet encrypted mesh network.
 *
 * @packageDocumentation
 */

// ── Main client ─────────────────────────────────────────────────────
export { GhostNet, GhostNet as Atlas } from './client.js';

// ── Types ───────────────────────────────────────────────────────────
export type {
  GhostNetOptions,
  GhostNetOptions as AtlasOptions,
  Identity,
  IncomingMessage,
  GhostNetEvents,
  GhostNetEvents as AtlasEvents,
  SecurityEvent,
  PeerInfo,
  NetworkStatus,
} from './types.js';

// ── FAQ Chatbot ────────────────────────────────────────────────────
export { GhostSupportBot } from './lib/GhostFAQ.js';

// ── Errors ──────────────────────────────────────────────────────────
export {
  GhostNetError,
  ConnectionError,
  IdentityError,
  EncryptionError,
  PeerNotFoundError,
  PayloadTooLargeError,
  RelayError,
  ReplayError,
  PeerVerificationError,
} from './errors.js';
