import express from 'express';
import { auth } from 'express-openid-connect';

const app = express();

app.use(
  auth({
    authRequired: true,
    issuerBaseURL: 'http://localhost:3000',
    baseURL: 'http://localhost:4000',
    clientID: 'mock-client',
    secret: 'longerthan32characters1231231',
    clientSecret: 'longerthan32characters1231231',
    authorizationParams: {
      scope: 'openid user_attributes profile',
      response_type: 'code',
    },
    routes: {
      callback: '/oidc-callback',
    },
  }),
);

app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(req.oidc.user));
});

app.listen(4000);
