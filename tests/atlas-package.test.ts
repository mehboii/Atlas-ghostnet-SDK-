import { describe, expect, it } from 'vitest';
import { Atlas, GhostNet } from '../src/index.js';

describe('Atlas package API', () => {
  it('exports Atlas and keeps GhostNet as a compatible alias', () => {
    expect(Atlas).toBe(GhostNet);
    const client = new Atlas({ endpoint: 'wss://relay.test' });
    expect(client.getStatus().connected).toBe(false);
    expect(client.getStatus().endpoint).toBe('wss://relay.test');
  });
});
