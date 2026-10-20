import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { inspectCli } from '../src/cli.js';

describe('Phase 4: CLI Commands & Option Handling', () => {
  let cliPath: string | null = null;

  it('locates the GhostNet native CLI binary', async () => {
    const status = await inspectCli();
    expect(status.available).toBe(true);
    expect(status.executable).toBeTruthy();
    expect(status.version).toMatch(/^0\.2\./);
    cliPath = status.executable;
  });

  function runCli(args: string[], env: Record<string, string> = {}) {
    if (!cliPath) throw new Error('CLI path not discovered');
    return spawnSync(cliPath, args, {
      encoding: 'utf8',
      env: { ...process.env, ...env },
    });
  }

  describe('Standard Commands & Syntax Verification', () => {
    it('--version prints valid version matching semver', () => {
      const res = runCli(['--version']);
      expect(res.status).toBe(0);
      expect(res.stdout).toMatch(/^ghostnet\s+0\.2\.\d+/i);
    });

    it('--help prints usage information for all subcommands', () => {
      const res = runCli(['--help']);
      expect(res.status).toBe(0);
      expect(res.stdout).toContain('GhostNet CLI');
      expect(res.stdout).toContain('setup');
      expect(res.stdout).toContain('info');
      expect(res.stdout).toContain('identity');
      expect(res.stdout).toContain('send');
      expect(res.stdout).toContain('listen');
    });

    it('info command displays CLI and SDK status', () => {
      const res = runCli(['info', '--no-color']);
      expect(res.status).toBe(0);
      expect(res.stdout).toContain('N 1 1 X   C O L L E C T I V E');
      expect(res.stdout).toContain('CLI version:  0.2.0');
      expect(res.stdout).toContain('SDK package:  @n11x/ghostnet-sdk');
      expect(res.stdout).toContain('SDK bridge:   installed');
    });

    it('identity create generates a fresh 12-word BIP-39 phrase and 0x Node ID', () => {
      const res = runCli(['identity', 'create', '--no-color']);
      expect(res.status).toBe(0);
      expect(res.stdout).toContain('New identity created');
      expect(res.stdout).toMatch(/Node ID:\s*0x[0-9a-f]{64}/i);
      expect(res.stdout).toMatch(/Seed phrase:\s*([a-z]+\s+){11}[a-z]+/i);
    });

    it('identity load restores the exact same Node ID deterministically', () => {
      const createRes = runCli(['identity', 'create', '--no-color']);
      const nodeMatch = /Node ID:\s*(0x[0-9a-f]{64})/i.exec(createRes.stdout);
      const seedMatch = /Seed phrase:\s*(([a-z]+\s+){11}[a-z]+)/i.exec(createRes.stdout);

      expect(nodeMatch).toBeTruthy();
      expect(seedMatch).toBeTruthy();

      const createdNodeId = nodeMatch![1];
      const seedPhrase = seedMatch![1].trim();

      // Load via positional argument
      const loadRes = runCli(['identity', 'load', '--no-color', seedPhrase]);
      expect(loadRes.status).toBe(0);
      expect(loadRes.stdout).toContain('Identity restored');
      expect(loadRes.stdout).toContain(createdNodeId);

      // Load via GHOSTNET_SEED environment variable
      const envRes = runCli(['identity', 'load', '--no-color'], { GHOSTNET_SEED: seedPhrase });
      expect(envRes.status).toBe(0);
      expect(envRes.stdout).toContain('Identity restored');
      expect(envRes.stdout).toContain(createdNodeId);
    });
  });

  describe('Error Handling, Invalid Arguments & Unknown Options', () => {
    it('unknown subcommand exits with non-zero exit code', () => {
      const res = runCli(['nonexistent-subcommand']);
      expect(res.status).not.toBe(0);
      expect(res.stderr + res.stdout).toMatch(/unrecognized subcommand|which wasn't expected/i);
    });

    it('unknown option flag exits with non-zero exit code', () => {
      const res = runCli(['--invalid-flag-xyz']);
      expect(res.status).not.toBe(0);
      expect(res.stderr + res.stdout).toMatch(/unexpected argument|unrecognized/i);
    });

    it('identity load with invalid phrase exits with error', () => {
      const res = runCli(['identity', 'load', '--no-color', 'not a real mnemonic seed phrase at all xyz']);
      expect(res.status).not.toBe(0);
      expect(res.stderr + res.stdout).toMatch(/error|invalid/i);
    });

    it('send with missing peer and message arguments exits with usage error', () => {
      const res = runCli(['send']);
      expect(res.status).not.toBe(0);
      expect(res.stderr + res.stdout).toMatch(/required argument|usage/i);
    });

    it('send with missing message argument exits with usage error', () => {
      const res = runCli(['send', '0x' + '1'.repeat(64)]);
      expect(res.status).not.toBe(0);
      expect(res.stderr + res.stdout).toMatch(/required argument|usage/i);
    });
  });
});
