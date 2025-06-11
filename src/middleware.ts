import express from 'express';
import { z } from 'zod';
import crypto from 'crypto';
import path from 'path';
import { mkdirSync, existsSync, writeFileSync, readFileSync } from 'fs';
import cookieParser from 'cookie-parser';

type User = {
  sub: string;
  [key: string]: unknown;
};

export type Options = {
  issuer: string;
  users: User[];
  baseClaims?: {
    [key: string]: unknown;
  };
  scopes?: {
    [key: string]: string[];
  };
  tokenExpiration?: number;
  keys?: {
    publicKey: string;
    privateKey: string;
  };
  logger?: {
    log: (...args: any[]) => void;
  };
};

const KID = 'mock-key-id';

// Basic PEM format regex (very permissive)
const pemRegex = /-----BEGIN ([A-Z ]+)-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END \1-----/;



const oidcMockServerMiddleware = ({ issuer, tokenExpiration = 3600, users, baseClaims, scopes, keys, logger = console }: Options) => {
  /**
  * Create JSON Web Key Set (JWKS) for the public key
  */
  function createJwks(publicKey: crypto.KeyObject): { keys: crypto.JsonWebKey[] } {
    const publicJwk = publicKey.export({ format: 'jwk' });
    return {
      keys: [{ ...publicJwk, alg: 'RS256', use: 'sig', kid: KID }],
    };
  }

  /**
   * Creates crypto.KeyObject instances for public and private keys.
   * If keys are provided, they are used; otherwise, a new key pair is generated and saved to disk.
   * @param keys 
   * @returns 
   */
  function resolveKeyObjects(keys?: { publicKey: string; privateKey: string }): { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject } {
    if (!keys) {
      logger.log('No keys provided in config, falling back to generating new key pair or loading from disk');
      return loadOrGenerateKeyPair();
    }

    logger.log('Creating key objects from provided PEM strings');
    const publicKey = crypto.createPublicKey({
      key: keys.publicKey,
      format: 'pem',
    });
    const privateKey = crypto.createPrivateKey({
      key: keys.privateKey,
      format: 'pem',
    });
    return { publicKey, privateKey };
  }

  /**
   * Generate or load from disk RSA key pair for signing tokens
   */
  function loadOrGenerateKeyPair(): { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject } {
    const dir = path.resolve(__dirname, '.keys');
    const publicKeyPath = path.join(dir, 'public.pem');
    const privateKeyPath = path.join(dir, 'private.pem');

    // Generate new key pair if not found
    if (!existsSync(privateKeyPath) || !existsSync(publicKeyPath)) {
      logger.log('No existing key pair found on disk, generating new key pair');
      if (!existsSync(dir)) mkdirSync(dir);

      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      writeFileSync(publicKeyPath, publicKey.export({ format: 'pem', type: 'spki' }));
      writeFileSync(privateKeyPath, privateKey.export({ format: 'pem', type: 'pkcs8' }));
      return { publicKey, privateKey };
    }

    logger.log('Found existing key pair, loading from disk');

    // Load existing key pair from disk
    return {
      privateKey: crypto.createPrivateKey({
        key: readFileSync(privateKeyPath, 'utf-8'),
        format: 'pem',
      }),
      publicKey: crypto.createPublicKey({
        key: readFileSync(publicKeyPath, 'utf-8'),
        format: 'pem',
      }),
    };
  }

  /**
   * Base64 URL encode a Buffer
   * @param input The input buffer to encode
   * @returns Base64 URL encoded string
   */
  function base64urlEncode(input: Buffer): string {
    return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Base64 URL decode a string
   * @param input The input string to decode
   * @returns Decoded buffer
   */
  function base64urlDecode(input: string): string {
    const padding = '='.repeat((4 - (input.length % 4)) % 4);
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/') + padding;
    return Buffer.from(base64, 'base64').toString('utf-8');
  }

  /**
   * Decode a JWT token and return its header and payload
   * This function assumes the JWT is well-formed and does not perform signature verification.
   * It is intended for use in a mock server context where the signature is not verified.
   * @param token The JWT token to decode
   * @returns The decoded header and payload
   */
  const decodeJwt = (token: string) => {
    const [headerEncoded, payloadEncoded] = token.split('.');

    // Decode and parse the header
    const header = JSON.parse(base64urlDecode(headerEncoded));

    // Decode and parse the payload
    const payload = JSON.parse(base64urlDecode(payloadEncoded));

    return { header, payload };
  };

  /**
   * Sign a JWT token with the given payload and private key
   * @param payload
   * @param privateKey
   * @param options
   * @returns Signed JWT token as string
   */
  function signJwt(payload: object, privateKey: crypto.KeyObject, options: { algorithm: string; keyid: string }) {
    const header = {
      alg: options.algorithm,
      typ: 'JWT',
      kid: options.keyid,
    };

    const headerEncoded = base64urlEncode(Buffer.from(JSON.stringify(header)));
    const payloadEncoded = base64urlEncode(Buffer.from(JSON.stringify(payload)));

    const dataToSign = `${headerEncoded}.${payloadEncoded}`;
    const signature = crypto.sign('sha256', Buffer.from(dataToSign), privateKey);

    return `${dataToSign}.${base64urlEncode(signature)}`;
  }

  /**
   * Validate the query parameters for the authorization request
   * This function checks if all required parameters are present and returns them in a structured format.
   * If any parameter is missing, it returns false.
   * @param payload 
   * @returns Validated query parameters or false if validation fails
   */
  function validateAuthQueryParams(payload: any):
    | false
    | {
      client_id: string;
      redirect_uri: string;
      code_challenge: string;
      code_challenge_method: string;
      response_type: string;
      state: string;
      nonce: string;
      scope: string;
    } {
    const { client_id, redirect_uri, code_challenge, code_challenge_method, response_type, state, nonce, scope } =
      payload;
    if (
      !client_id ||
      !redirect_uri ||
      !code_challenge ||
      !code_challenge_method ||
      !response_type ||
      !state ||
      !nonce ||
      !scope
    ) {
      return false;
    }

    return {
      client_id: client_id.toString(),
      redirect_uri: redirect_uri.toString(),
      code_challenge: code_challenge.toString(),
      code_challenge_method: code_challenge_method.toString(),
      response_type: response_type.toString(),
      state: state.toString(),
      nonce: nonce.toString(),
      scope: scope.toString(),
    };
  }


  logger.log('Initializing OIDC mock server middleware');
  try {
    z.object({
      issuer: z.string().url(),
      users: z.array(z.object({ sub: z.string() })),
      baseClaims: z.object({}).optional(),
      scopes: z.record(z.string(), z.array(z.string())).optional(),
      keys: z.object({
        publicKey: z.string().refine((val) => pemRegex.test(val), { message: 'Invalid public key PEM format' }),
        privateKey: z.string().refine((val) => pemRegex.test(val), { message: 'Invalid private key PEM format' }),
      }).optional(),
    }).parse({ issuer, users, baseClaims, scopes });
  } catch (error) {
    if (error instanceof z.ZodError) {
      const formattedErrors = error.errors.map(err => `${err.path.join('.')}: ${err.message}`).join(', ');
      throw new Error(`Invalid configuration: ${formattedErrors}`);
    }
    throw error; // Re-throw unexpected errors
  }

  const router = express.Router();
  const { publicKey, privateKey } = resolveKeyObjects(keys);
  const jwks = createJwks(publicKey);
  const userSessions = new Set<string>();
  const authCodes = new Map<
    string,
    {
      code: string;
      client_id: string;
      redirect_uri: string;
      code_challenge: string;
      code_challenge_method: string;
      sub: string;
      response_type: string;
      nonce: string;
      scope: string;
    }
  >();

  router.use(express.urlencoded({ extended: true }));
  router.use(express.json());
  router.use(cookieParser());

  router.get('/oauth/authorize', (req, res) => {
    const sid = req.cookies.sid as string | undefined;
    const hasSession = sid ? userSessions.has(sid) : false;

    // Show login form if no session exists
    if (!hasSession) {
      const query = new URLSearchParams(req.query as any).toString();
      res.send(`
            <div style="display: flex; flex-direction: column; align-items: center; height: 100vh; justify-content: center;">
              <form method="POST" action="/login?${query}">
                <input name="username" placeholder="Username" required />
                <button type="submit">Login</button>
              </form>
            </div>
          `);
      return;
    }

    const queryParams = validateAuthQueryParams(req.query);
    if (!queryParams) {
      res.status(400).json({ error: 'Invalid request' });
      return;
    }

    const code = crypto.randomUUID();
    authCodes.set(code, {
      code,
      sub: sid!,
      ...queryParams,
    });
    return res.redirect(`${queryParams.redirect_uri}?code=${code}&state=${queryParams.state}`);
  });

  router.post('/login', (req, res) => {
    const { username } = req.body;
    if (!username || !users.some(user => user.sub === username)) {
      res.status(400).send(`
            <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh;">
              <h2>Invalid login credentials</h2>
              <a href="javascript:history.back()">Go back</a>
            </div>
          `);
      return;
    }

    const sid = req.body.username as string;

    const queryParams = validateAuthQueryParams(req.query);
    if (!queryParams) {
      res.status(400).json({ error: 'Invalid request' });
      return;
    }

    userSessions.add(sid);
    res.cookie('sid', sid, { httpOnly: true });

    const code = crypto.randomUUID();
    authCodes.set(code, {
      code,
      sub: sid,
      ...queryParams,
    });
    res.redirect(`${queryParams.redirect_uri}?code=${code}&state=${queryParams.state}`);
  });

  router.post('/oauth/token', (req, res) => {
    const { code, code_verifier } = req.body;
    const auth = authCodes.get(code);

    if (!auth) {
      res.status(400).json({ error: 'Invalid code' });
      return;
    }

    const expected =
      auth.code_challenge_method === 'S256'
        ? base64urlEncode(crypto.createHash('sha256').update(code_verifier).digest())
        : code_verifier;

    if (expected !== auth.code_challenge) {
      res.status(400).json({ error: 'Invalid code_verifier' });
      authCodes.delete(code);
      return;
    }

    const user = users.find(u => u.sub === auth.sub);
    if (!user) {
      res.status(500).json({ error: `User with sub ${auth.sub} does not exist.` });
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const requiredClaims = {
      sub: user.sub,
      iss: issuer,
      aud: auth.client_id,
      exp: now + tokenExpiration,
      iat: now,
      nonce: auth.nonce,
    };

    const attributes = {
      ...baseClaims,
      ...user,
    };

    const requestedScopes = auth.scope.split(' ');
    const requestedClaims = requestedScopes.reduce<Record<string, unknown>>((acc, scope) => {
      const claims = scopes?.[scope];
      if (claims) {
        claims.forEach(claim => {
          acc[claim] = attributes[claim];
        });
      }
      return acc;
    }, {});

    const token = signJwt({ ...requiredClaims, ...requestedClaims }, privateKey, { algorithm: 'RS256', keyid: KID });
    authCodes.delete(code);

    res.json({
      access_token: token,
      id_token: token,
      token_type: 'Bearer',
      expires_in: tokenExpiration,
    });
  });

  // Userinfo endpoint: returns user information based on the provided token
  router.get('/userinfo', (req, res) => {
    const token = (req.headers.authorization || '').split(' ')[1];
    if (!token) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    try {
      const decoded = decodeJwt(token);
      const { sub } = decoded.payload;
      const user = users.find(u => u.sub === sub);
      if (!user) {
        res.status(500).json({ error: `User with sub ${sub} does not exist.` });
        return;
      }
    } catch {
      res.status(401).json({ error: 'Invalid token' });
    }
  });

  // OpenID configuration endpoint: Provides metadata about the OIDC provider
  router.get('/.well-known/openid-configuration', (_, res) => {
    res.json({
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/token_keys`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: Array.from(new Set(['openid', ...Object.keys(scopes || {})])),
      code_challenge_methods_supported: ['S256', 'plain'],
    });
  });

  // JWKS endpoint: Returns the public key in JWKS format
  router.get('/token_keys', (_, res) => {
    res.json(jwks);
  });

  logger.log('OIDC mock server middleware initialized successfully');

  return router;
};

export default oidcMockServerMiddleware;
