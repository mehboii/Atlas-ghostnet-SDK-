import { describe, expect, it } from 'vitest';
import { inspectCli } from '../src/cli.js';

describe('CLI discovery', () => {
  it('reports a missing explicitly configured CLI without installing or launching one', async () => {
    const result = await inspectCli('./definitely-missing-ghostnet-cli');
    expect(result.available).toBe(false);
    expect(result.executable).toBeNull();
    expect(result.detail).toContain('No compatible GhostNet native executable');
  });

  const binary = process.env.GHOSTNET_CLI_PATH;
  it.skipIf(!binary)('recognizes a real installed CLI binary', async () => {
    const result = await inspectCli(binary);
    expect(result.available).toBe(true);
    expect(result.compatible).toBe(true);
    expect(result.version).toMatch(/^0\.2\./);
  });
});
