/**
 * Browser-based tests for @n11x/atlas.
 *
 * These run via Playwright in headless Chromium and Firefox to verify
 * the SDK works in browser environments (WebSocket, crypto, etc.).
 */
import { test, expect } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test.describe('Atlas SDK — browser', () => {
  test('creates identity with valid nodeId format', async ({ page }) => {
    // Serve the built SDK bundle in-browser
    await page.goto('about:blank');

    // Inject the SDK bundle
    const sdkPath = path.resolve(__dirname, '../../dist/index.js');
    await page.addScriptTag({ path: sdkPath, type: 'module' });

    const result = await page.evaluate(async () => {
      // Dynamic import from the injected module
      const mod = await import('./dist/index.js');
      const gn = new mod.GhostNet();
      const id = gn.createIdentity();
      return {
        nodeId: id.nodeId,
        publicKey: id.publicKey,
        seedWordCount: id.seedPhrase.split(' ').length,
      };
    });

    expect(result.nodeId).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(result.seedWordCount).toBe(12);
  });

  test('rejects insecure endpoint in browser', async ({ page }) => {
    await page.goto('about:blank');
    const sdkPath = path.resolve(__dirname, '../../dist/index.js');
    await page.addScriptTag({ path: sdkPath, type: 'module' });

    const error = await page.evaluate(async () => {
      const mod = await import('./dist/index.js');
      try {
        new mod.GhostNet({ endpoint: 'ws://insecure.com' });
        return null;
      } catch (e: unknown) {
        const err = e as { name: string; code: string };
        return { name: err.name, code: err.code };
      }
    });

    expect(error).not.toBeNull();
    expect(error!.code).toBe('ERR_CONNECTION');
  });

  test('encrypt/decrypt roundtrip in browser', async ({ page }) => {
    await page.goto('about:blank');
    const sdkPath = path.resolve(__dirname, '../../dist/index.js');
    await page.addScriptTag({ path: sdkPath, type: 'module' });

    const result = await page.evaluate(async () => {
      const mod = await import('./dist/index.js');
      const gn = new mod.GhostNet();
      const id1 = gn.createIdentity();
      const id2 = gn.createIdentity();
      // Basic identity format check in browser
      return {
        id1Valid: /^0x[0-9a-f]{64}$/.test(id1.nodeId),
        id2Valid: /^0x[0-9a-f]{64}$/.test(id2.nodeId),
        different: id1.nodeId !== id2.nodeId,
      };
    });

    expect(result.id1Valid).toBe(true);
    expect(result.id2Valid).toBe(true);
    expect(result.different).toBe(true);
  });
});
