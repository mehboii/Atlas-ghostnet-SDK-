/**
 * Base error class for Atlas SDK errors.
 *
 * @example
 * ```ts
 * try {
 *   await ghostnet.connect();
 * } catch (err) {
 *   if (err instanceof GhostNetError) {
 *     console.error(`[${err.code}] ${err.message}`);
 *   }
 * }
 * ```
 */
export class GhostNetError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'GhostNetError';
    this.code = code;
  }
}

/**
 * Thrown when a WebSocket connection fails or is unexpectedly closed.
 *
 * @example
 * ```ts
 * ghostnet.on('error', (err) => {
 *   if (err instanceof ConnectionError) {
 *     console.error('Connection lost:', err.message);
 *   }
 * });
 * ```
 */
export class ConnectionError extends GhostNetError {
  constructor(message: string) {
    super(message, 'ERR_CONNECTION');
    this.name = 'ConnectionError';
  }
}

/**
 * Thrown when identity creation or loading fails.
 *
 * @example
 * ```ts
 * try {
 *   const identity = ghostnet.loadIdentity('invalid words');
 * } catch (err) {
 *   if (err instanceof IdentityError) {
 *     console.error('Bad seed phrase:', err.message);
 *   }
 * }
 * ```
 */
export class IdentityError extends GhostNetError {
  constructor(message: string) {
    super(message, 'ERR_IDENTITY');
    this.name = 'IdentityError';
  }
}

/**
 * Thrown when message encryption or decryption fails.
 *
 * @example
 * ```ts
 * try {
 *   await ghostnet.send(peerId, 'hello');
 * } catch (err) {
 *   if (err instanceof EncryptionError) {
 *     console.error('Encryption failed:', err.message);
 *   }
 * }
 * ```
 */
export class EncryptionError extends GhostNetError {
  constructor(message: string) {
    super(message, 'ERR_ENCRYPTION');
    this.name = 'EncryptionError';
  }
}

/**
 * Thrown when a message is sent to an unknown or unreachable peer.
 *
 * @example
 * ```ts
 * try {
 *   await ghostnet.send('0xdeadbeef...', 'hello');
 * } catch (err) {
 *   if (err instanceof PeerNotFoundError) {
 *     console.error('Peer offline:', err.peerId);
 *   }
 * }
 * ```
 */
export class PeerNotFoundError extends GhostNetError {
  readonly peerId: string;

  constructor(peerId: string) {
    super(`Peer not found: ${peerId}`, 'ERR_PEER_NOT_FOUND');
    this.name = 'PeerNotFoundError';
    this.peerId = peerId;
  }
}

/**
 * Thrown when the message payload exceeds the maximum allowed size.
 *
 * @example
 * ```ts
 * try {
 *   await ghostnet.send(peerId, hugePayload);
 * } catch (err) {
 *   if (err instanceof PayloadTooLargeError) {
 *     console.error(`Max size: ${err.maxBytes} bytes`);
 *   }
 * }
 * ```
 */
export class PayloadTooLargeError extends GhostNetError {
  readonly actualBytes: number;
  readonly maxBytes: number;

  constructor(actualBytes: number, maxBytes: number) {
    super(
      `Payload too large: ${actualBytes} bytes exceeds ${maxBytes} byte limit`,
      'ERR_PAYLOAD_TOO_LARGE',
    );
    this.name = 'PayloadTooLargeError';
    this.actualBytes = actualBytes;
    this.maxBytes = maxBytes;
  }
}

/**
 * Thrown when the relay server reports a protocol-level error.
 *
 * @example
 * ```ts
 * ghostnet.on('error', (err) => {
 *   if (err instanceof RelayError) {
 *     console.error('Relay rejected:', err.relayCode);
 *   }
 * });
 * ```
 */
export class RelayError extends GhostNetError {
  readonly relayCode: string;

  constructor(message: string, relayCode: string) {
    super(message, 'ERR_RELAY');
    this.name = 'RelayError';
    this.relayCode = relayCode;
  }
}

/**
 * Thrown when a message fails replay protection checks.
 *
 * @example
 * ```ts
 * ghostnet.on('error', (err) => {
 *   if (err instanceof ReplayError) {
 *     console.error('Replay attack detected:', err.nonce);
 *   }
 * });
 * ```
 */
export class ReplayError extends GhostNetError {
  readonly nonce: string;

  constructor(nonce: string) {
    super(`Replayed message detected (nonce: ${nonce})`, 'ERR_REPLAY');
    this.name = 'ReplayError';
    this.nonce = nonce;
  }
}

/**
 * Thrown when a peer's cryptographic announcement fails verification.
 *
 * @example
 * ```ts
 * ghostnet.on('error', (err) => {
 *   if (err instanceof PeerVerificationError) {
 *     console.error('Untrusted peer:', err.peerId);
 *   }
 * });
 * ```
 */
export class PeerVerificationError extends GhostNetError {
  readonly peerId: string;

  constructor(peerId: string, reason: string) {
    super(`Peer verification failed for ${peerId}: ${reason}`, 'ERR_PEER_VERIFICATION');
    this.name = 'PeerVerificationError';
    this.peerId = peerId;
  }
}
