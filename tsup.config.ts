import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/index.ts', 'src/cli.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    splitting: false,
    treeshake: true,
    target: 'es2022',
    outDir: 'dist',
  },
  {
    entry: ['src/index.ts'],
    format: ['iife'],
    globalName: 'AtlasSDK',
    sourcemap: true,
    splitting: false,
    treeshake: true,
    target: 'es2022',
    outDir: 'dist',
    outExtension: () => ({ js: '.browser.js' }),
    noExternal: [/.*/],
    platform: 'browser',
  },
]);
