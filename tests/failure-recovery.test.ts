import { describe, it, expect, vi } from 'vitest';
import {
  GhostNet,
  RelayError,
  EncryptionError,
  IdentityError,
} from '../src/index.js';

describe('Phase 8: Failure Injection & Recovery', () => {
  it('gracefully handles and drops primitive JSON frames (null, number, boolean) without throwing', async () => {
    const gn = new GhostNet();
    gn.createIdentity();

    // Call private handleIncoming with primitive frames
    const handleIncoming = (gn as unknown as { handleIncoming: (raw: string) => Promise<void> }).handleIncoming.bind(gn);

    await expect(handleIncoming('null')).resolves.toBeUndefined();
    await expect(handleIncoming('42')).resolves.toBeUndefined();
    await expect(handleIncoming('true')).resolves.toBeUndefined();
    await expect(handleIncoming('false')).resolves.toBeUndefined();
    await expect(handleIncoming('"just a string"')).resolves.toBeUndefined();
    await expect(handleIncoming('[]')).resolves.toBeUndefined();
    await expect(handleIncoming('{}')).resolves.toBeUndefined();
    await expect(handleIncoming('{ "type": 123 }')).resolves.toBeUndefined();
  });

  it('surfaces RelayError with custom relayCode when relay sends an error frame', async () => {
    const gn = new GhostNet();
    gn.createIdentity();

    const errors: Error[] = [];
    gn.on('error', (err) => errors.push(err));

    const handleIncoming = (gn as unknown as { handleIncoming: (raw: string) => Promise<void> }).handleIncoming.bind(gn);

    await handleIncoming(
      JSON.stringify({
        type: 'error',
        payload: 'Too many requests from node',
        relayCode: 'ERR_RATE_LIMIT_EXCEEDED',
      }),
    );

    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(RelayError);
    const relayErr = errors[0] as RelayError;
    expect(relayErr.code).toBe('ERR_RELAY');
    expect(relayErr.relayCode).toBe('ERR_RATE_LIMIT_EXCEEDED');
    expect(relayErr.message).toBe('Too many requests from node');
  });

  it('rejects corrupted encrypted payload with typed EncryptionError', async () => {
    const gn = new GhostNet({ requireEncryption: false });
    const id = gn.createIdentity();

    const handleIncoming = (gn as unknown as { handleIncoming: (raw: string) => Promise<void> }).handleIncoming.bind(gn);

    // Corrupted base64 payload
    await expect(
      handleIncoming(
        JSON.stringify({
          type: 'message',
          from: '0x' + '1'.repeat(64),
          to: id.nodeId,
          payload: 'not-valid-base-64-!!!',
          encrypted: true,
          nonce: '1234567890abcdef',
          timestamp: Date.now(),
        }),
      ),
    ).rejects.toThrow(EncryptionError);
  });

  it('prevents accidental message forgery after identity disposal', async () => {
    const gn = new GhostNet();
    const id = gn.createIdentity();
    id.dispose();

    await expect(gn.send('0x' + '2'.repeat(64), 'secret')).rejects.toThrow(IdentityError);
  });

  it('surfaces security event when receiving replay message without corrupting state', async () => {
    const gn = new GhostNet({ requireEncryption: false });
    const id = gn.createIdentity();

    const secEvents: Array<{ type: string; detail: string }> = [];
    gn.on('security', (ev) => secEvents.push(ev));
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    const handleIncoming = (gn as unknown as { handleIncoming: (raw: string) => Promise<void> }).handleIncoming.bind(gn);

    const validEnvelope = {
      type: 'message',
      from: '0x' + '3'.repeat(64),
      to: id.nodeId,
      payload: 'plaintext',
      encrypted: false,
      nonce: 'fixed-replay-nonce-1',
      timestamp: Date.now(),
    };

    // First arrival: processed
    await handleIncoming(JSON.stringify(validEnvelope));

    // Replay arrival: dropped with security event
    await handleIncoming(JSON.stringify(validEnvelope));

    expect(secEvents.some((e) => e.type === 'replay_detected')).toBe(true);
  });
});
