const esbuild = require('esbuild');

esbuild
  .build({
    entryPoints: ['src/index.ts'], // Entry point for your package
    bundle: true, // Bundle all dependencies into one file
    platform: 'node', // Target Node.js environment
    outfile: 'dist/index.js', // Output file
    sourcemap: true, // Generate source maps
    target: 'node22', // Specify the Node.js version
    external: ['express', 'cookie-parser'], // Mark dependencies as external
    format: 'cjs',
  })
  .catch(() => process.exit(1));
