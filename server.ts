import express from 'express';
import oidcMockServerMiddleware from './src/middleware';
import fs from 'fs';

const app = express();
const port = +(process.env.PORT || 3000);
const host = process.env.HOST || `http://localhost`;

const issuer = `${host}:${port}`;

const configFilePath = process.env.CONFIG_PATH || './server-config.json';
let config: any;

try {
  const configFileContent = fs.readFileSync(configFilePath, 'utf8');
  config = JSON.parse(configFileContent);
} catch (error) {
  console.error(`Error reading or parsing config file: ${error}`);
  process.exit(1);
}

const publicKey = process.env.PUBLIC_KEY_PEM;
const privateKey = process.env.PRIVATE_KEY_PEM;

const keys = typeof publicKey === 'string' && typeof privateKey === 'string' ? {
  publicKey,
  privateKey
} : undefined;

app.use(oidcMockServerMiddleware({ ...config, issuer, keys }));

app.listen(port, () => {
  console.log(`OIDC mock server running on ${host}:${port}`);
});
