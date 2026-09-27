#!/usr/bin/env node

/**
 * create-ghostnet-app — Scaffold a new Atlas SDK project.
 *
 * Usage:
 *   npx create-ghostnet-app my-app
 *   npx create-ghostnet-app my-app --template minimal
 */

import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { execSync } from 'node:child_process';

const args = process.argv.slice(2);
const projectName = args[0];
const template = args.includes('--template') ? args[args.indexOf('--template') + 1] : 'default';

if (!projectName) {
  console.log(`
  Usage: npx create-ghostnet-app <project-name> [--template minimal|default]

  Templates:
    default  — Full setup with identity, connect, send/receive
    minimal  — Bare minimum to get started
  `);
  process.exit(1);
}

const projectDir = resolve(projectName);

if (existsSync(projectDir)) {
  console.error(`Error: Directory "${projectName}" already exists.`);
  process.exit(1);
}

console.log(`\nCreating GhostNet app: ${projectName}\n`);

mkdirSync(projectDir, { recursive: true });
mkdirSync(join(projectDir, 'src'), { recursive: true });

// package.json
writeFileSync(join(projectDir, 'package.json'), JSON.stringify({
  name: projectName,
  version: '0.1.0',
  private: true,
  type: 'module',
  scripts: {
    start: 'node --loader ts-node/esm src/index.ts',
    build: 'tsc',
    dev: 'node --loader ts-node/esm --watch src/index.ts',
  },
  dependencies: {
    '@n11x/atlas': 'latest',
  },
  devDependencies: {
    'typescript': '^5.0.0',
    'ts-node': '^10.9.0',
    '@types/node': '^22.0.0',
  },
}, null, 2) + '\n');

// tsconfig.json
writeFileSync(join(projectDir, 'tsconfig.json'), JSON.stringify({
  compilerOptions: {
    target: 'ES2022',
    module: 'ES2022',
    moduleResolution: 'bundler',
    strict: true,
    esModuleInterop: true,
    outDir: './dist',
    rootDir: './src',
    declaration: true,
  },
  include: ['src'],
}, null, 2) + '\n');

// .gitignore
writeFileSync(join(projectDir, '.gitignore'), `node_modules/
dist/
.env
.env.*
*.log
`);

// .env.example
writeFileSync(join(projectDir, '.env.example'), `# Atlas SDK Configuration
# GHOSTNET_RELAY_URL=wss://staging-relay.example.com
# GHOSTNET_DEBUG=true
`);

// Source file based on template
const templates = {
  minimal: `import { Atlas } from '@n11x/atlas';

const gn = new Atlas({ debug: true });
const identity = gn.createIdentity();

console.log('Your GhostNet Node ID:', identity.nodeId);
console.log('Save your seed phrase securely:', identity.seedPhrase);
`,

  default: `import { Atlas, ConnectionError, PeerNotFoundError } from '@n11x/atlas';
import type { IncomingMessage } from '@n11x/atlas';

async function main() {
  // Initialize the SDK
  const gn = new Atlas({
    endpoint: process.env.GHOSTNET_RELAY_URL || undefined,
    debug: process.env.GHOSTNET_DEBUG === 'true',
  });

  // Create a new identity (or restore from seed phrase)
  const identity = gn.createIdentity();
  console.log('Node ID:', identity.nodeId);
  console.log('Seed phrase (save this!):', identity.seedPhrase);

  // Set up event handlers
  gn.on('connect', () => {
    console.log('Connected to GhostNet relay');
  });

  gn.on('disconnect', (reason) => {
    console.log('Disconnected:', reason);
  });

  gn.on('message', (msg: IncomingMessage) => {
    console.log(\`Message from \${msg.from}: \${msg.data}\`);
  });

  gn.on('error', (err) => {
    if (err instanceof PeerNotFoundError) {
      console.error('Peer not found:', err.peerId);
    } else if (err instanceof ConnectionError) {
      console.error('Connection error:', err.message);
    } else {
      console.error('Error:', err.message);
    }
  });

  // Connect to the relay
  try {
    await gn.connect();
    console.log('Ready! Share your Node ID with peers to start messaging.');
  } catch (err) {
    console.error('Failed to connect:', err);
    process.exit(1);
  }

  // To send a message to a peer:
  // await gn.send('0xPEER_NODE_ID', 'Hello from GhostNet!');

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\\nShutting down...');
    gn.disconnect();
    identity.dispose();
    process.exit(0);
  });
}

main();
`,
};

const sourceCode = templates[template] || templates.default;
writeFileSync(join(projectDir, 'src/index.ts'), sourceCode);

// README
writeFileSync(join(projectDir, 'README.md'), `# ${projectName}

Built with [@n11x/atlas](https://github.com/n11x/ghostnet-sdk).

## Getting Started

\`\`\`bash
npm install
npm start
\`\`\`

## Environment Variables

Copy \`.env.example\` to \`.env\` and configure:

- \`GHOSTNET_RELAY_URL\` — Custom relay endpoint (optional)
- \`GHOSTNET_DEBUG\` — Enable debug logging

## Sending Messages

\`\`\`ts
await gn.send('0xPEER_NODE_ID', 'Hello!');
\`\`\`

## Restoring Identity

\`\`\`ts
const identity = gn.loadIdentity('your twelve word seed phrase here ...');
\`\`\`
`);

console.log('  Created project structure:');
console.log(`    ${projectName}/`);
console.log('    ├── src/index.ts');
console.log('    ├── package.json');
console.log('    ├── tsconfig.json');
console.log('    ├── .gitignore');
console.log('    ├── .env.example');
console.log('    └── README.md');

// Install dependencies
console.log('\n  Installing dependencies...\n');
try {
  execSync('npm install', { cwd: projectDir, stdio: 'inherit' });
} catch {
  console.log('\n  npm install failed. Run it manually:');
  console.log(`    cd ${projectName} && npm install\n`);
}

console.log(`
  Done! Get started:

    cd ${projectName}
    npm start

  Happy hacking!
`);
