import { access, realpath, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { delimiter, dirname, extname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';

/** The CLI is a separate process that uses this SDK. It has no attachable daemon. */
export interface CliStatus {
  available: boolean;
  executable: string | null;
  version: string | null;
  compatible: boolean;
  bridgeInstalled: boolean;
  detail: string;
}

async function exists(path: string): Promise<boolean> {
  try { await access(path); return true; } catch { return false; }
}

async function isDirectory(path: string): Promise<boolean> {
  try {
    const s = await stat(path);
    return s.isDirectory();
  } catch {
    return false;
  }
}

function versionOf(executable: string): Promise<string | null> {
  return new Promise((done) => {
    let settled = false;
    let child: ReturnType<typeof spawn> | null = null;

    const finish = (result: string | null) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        done(result);
      }
    };

    const timer = setTimeout(() => {
      try {
        child?.kill();
      } catch {
        // Child already terminated or failed to spawn
      }
      finish(null);
    }, 3000);
    if (typeof timer.unref === 'function') timer.unref();

    try {
      child = spawn(executable, ['--version'], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch {
      finish(null);
      return;
    }

    let output = '';
    child.stdout?.on('data', (chunk: Buffer) => {
      if (output.length < 256) output += chunk.toString();
    });
    child.on('error', () => {
      finish(null);
    });
    child.on('close', (code) => {
      const match = code === 0 ? /^ghostnet\s+(\d+\.\d+\.\d+(?:-[\w.]+)?)/im.exec(output) : null;
      finish(match?.[1] ?? null);
    });
  });
}

/** Locate the native `ghostnet` binary without invoking npm shell shims. */
export async function inspectCli(cliPath?: string): Promise<CliStatus> {
  const binaryName = process.platform === 'win32' ? 'ghostnet.exe' : 'ghostnet';
  let paths: string[];

  if (cliPath) {
    const resolved = resolve(cliPath);
    paths = [
      resolved,
      ...(process.platform === 'win32' && !extname(resolved) ? [
        `${resolved}.exe`,
        `${resolved}.cmd`,
        `${resolved}.ps1`,
      ] : []),
      join(resolved, binaryName),
      join(resolved, 'bin', binaryName),
      join(resolved, 'scripts', 'bin', binaryName),
    ];
  } else {
    paths = (process.env.PATH ?? '').split(delimiter).filter(Boolean).flatMap((dir) =>
      process.platform === 'win32'
        ? [join(dir, 'ghostnet.exe'), join(dir, 'ghostnet.cmd'), join(dir, 'ghostnet.ps1'), join(dir, 'ghostnet')]
        : [join(dir, 'ghostnet')]);
  }

  for (const candidate of paths) {
    if (!(await exists(candidate))) continue;
    if (await isDirectory(candidate)) continue;

    let executable = candidate;
    const extension = extname(candidate).toLowerCase();

    // Check for npm shims (.cmd, .ps1, or extensionless shell script on Windows)
    if (extension === '.cmd' || extension === '.ps1' || (process.platform === 'win32' && extension === '')) {
      const shimTarget = join(
        dirname(candidate),
        'node_modules',
        '@n11x',
        'ghostnet-cli',
        'scripts',
        'bin',
        binaryName,
      );
      if (await exists(shimTarget)) {
        executable = shimTarget;
      }
    } else if (extension === '.js' || extension === '.mjs' || process.platform !== 'win32') {
      const actual = await realpath(candidate).catch(() => candidate);
      if (actual.endsWith('run.js')) {
        executable = join(dirname(actual), 'bin', binaryName);
      }
    }

    if (await isDirectory(executable)) continue;
    if (!(await exists(executable))) continue;

    const version = await versionOf(executable);
    if (!version) continue;

    const compatible = /^0\.2\./.test(version);
    const home = homedir() || process.env.USERPROFILE || process.env.HOME;
    const bridgeInstalled = home
      ? await exists(join(home, '.ghostnet-cli', 'bridge', 'node_modules', '@n11x', 'ghostnet-sdk'))
      : false;

    return {
      available: true,
      executable,
      version,
      compatible,
      bridgeInstalled,
      detail: compatible
        ? bridgeInstalled
          ? 'CLI GhostNet SDK bridge detected. Atlas uses the same relay protocol.'
          : 'CLI detected; run `ghostnet setup` to install its SDK bridge.'
        : `CLI ${version} has not been verified with this SDK protocol.`,
    };
  }

  return {
    available: false,
    executable: null,
    version: null,
    compatible: false,
    bridgeInstalled: false,
    detail: cliPath
      ? `No compatible GhostNet native executable found at ${cliPath}.`
      : 'GhostNet CLI not found on PATH. Install @n11x/ghostnet-cli or provide cliPath.',
  };
}
