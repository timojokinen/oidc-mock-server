import express from 'express';
import oidcMockServerMiddleware from './src/middleware';
import fs from 'fs';

const app = express();
const port = process.env.PORT || 3000;
const ISSUER = `http://localhost:${port}`;

const configFilePath = process.env.CONFIG_PATH || './server-config.json';
let config: any;

try {
  const configFileContent = fs.readFileSync(configFilePath, 'utf8');
  config = JSON.parse(configFileContent);
} catch (error) {
  console.error(`Error reading or parsing config file: ${error}`);
  process.exit(1);
}

console.log({ ...config, issuer: ISSUER });

app.use(oidcMockServerMiddleware({ ...config, issuer: ISSUER }));

app.listen(port, () => {
  console.log(`OIDC mock server running on port ${port}`);
});
