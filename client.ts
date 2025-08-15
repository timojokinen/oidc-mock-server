import express from 'express';
import { auth } from 'express-openid-connect';

const app = express();

app.use(
  auth({
    idpLogout: true,
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
      logout: '/logout',
    },
  }),
);

app.get('/', (req, res) => {
  res.send(`<div><pre>${JSON.stringify(req.oidc.user, null, 2)}</pre>
  <a href="http://localhost:4000/logout">Logout</a></div>`)
});

app.listen(4000, () => {
  console.log('Server is running on http://localhost:4000');
});
