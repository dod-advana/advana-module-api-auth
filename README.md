## Configuration

**NOTE: For working with encrypted TLS/SSL connections to RDS (PostgreSQL) and ElastiCache (Redis) in the CSN AWS dev and test environments, you will need to include the Amazon Root CA and RDS us-east-1 certificates in your CA bundle (`TLS_CERT_CA` or `TLS_CERT_CA_FILEPATH`): [csn-aws.pem](./csn-aws.pem)**

| Environment Variable | Default Value | Description |
| ---                  | ---           | ---         |
| `AD_ENABLED` | | Set to `true` to query Active Directory for user permissions. |
| `API_AUTH_LOG_LEVEL` | `${LOG_LEVEL}` or `info` | The name of the lowest level of log messages to record from the module in development/testing environments. If this value is not set, it will inherit the value of the `LOG_LEVEL` setting if available or fall back to `info`. To disable log messages from the module, set this variable to `silent`.
| `APPROVED_API_CALLERS` | | A space-delimited list of URLs to use in generating the [`Access-Control-Allow-Origin` HTTP response header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin) in the `getAllowedOriginMiddleware`, also used to enforce safe client redirection in the SSO workflow. |
| `COOKIE_DOMAIN` | | The session cookie's [`Domain` attribute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#domaindomain-value) in the `redisSession` middleware. |
| `DISABLE_SSO` | | Set to `true` to disable SSO in development/testing environments. When `true`, the user will be defined by the value of the `SSL_CLIENT_S_DN_CN` HTTP request header. |
| `EXPRESS_SESSION_MAX_AGE` | `43200000` (12 hours) | The maximum session age (in milliseconds) allowed by the `redisSession` middleware. |
| `EXPRESS_SESSION_SECRET` | | A string that can be parsed as a JSON array for values to be used as the session secret for the `redisSession` middleware. |
| `LDAP_CERT` | | The certificate for the Active Directory server. |
| `LDAP_PASSWORD` | | The password for authenticating to the Active Directory server. |
| `LDAP_URL` | | The URL of the Active Directory server. |
| `LDAP_USER_FOLDER_CN` | | The root DN to search for users on the Active Directory server. |
| `LDAP_USERNAME` | | The username for authenticating to the Active Directory server. |
| `PG_HOST` | | The host name of the PostgreSQL database server where user data is stored. |
| `PG_PASSWORD` | | The password for authenticating to the PostgreSQL database server. |
| `PG_SSL_REQUIRE` | `true` | Set to `false` to connect to a local PostgreSQL server without SSL. Setting this to false will log a warning message when connecting to the `PG_UM_DB` database. |
| `PG_UM_DB` | | The name of the PostgreSQL database where user data is stored. |
| `PG_USER` | | The username for authenticating to the PostgreSQL database server. |
| `REDIS_PASSWORD` | | The password to use for authenticating to the Redis server. |
| `REDIS_URL` | `redis://localhost` | The URL of the Redis server that stores user session data by the `redisSession` middleware. |
| `REDIS_USER` | | The username to use for authenticating to the Redis server. |
| `SAML_CALLBACK_URL` | | The full callback URL for the identity provider's single sign-on (SSO) service. |
| `SAML_CERT` | | The public signing certificate for the identity provider used to validate signatures of incoming SAML responses. |
| `SAML_ENTRYPOINT` | | The identity provider's single sign-on (SSO) service entrypoint. |
| `SAML_ISSUER` | | The issuer string for the identity provider. |
| `SAML_LOGOUT_CALLBACK_URL` | | The value for the `Location` attribute in the identity provider's single logout (SLO) service configuration. |
| `SAML_LOGOUT_URL` | | The full URL for the identity provider's single logout (SLO) service). |
| `SECURE_SESSION` | | Boolean value determining how to secure the session cookie in the `redisSession` middleware. Set to *true* to set the session cookie's [`Secure` attibute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#secure) to `true` and the [`SameSite` attibute](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value) to `none`. Otherwise, these attributes will be set to `false` and `lax`, respectively. |
| `TLS_CERT_CA` | | The serialized certificate authority bundle for establishing encrypted TLS/SSL connections to PostgreSQL and Redis. |
| `TLS_CERT_CA_FILEPATH` | | The file path of the certificate authority bundle for establishing encrypted TLS/SSL connections to PostgreSQL and Redis, if `TLS_CERT_CA` is not defined. |
| `TLS_KEY` | | The private certificate for signing JWT tokens for client-side session management. |
| `TLS_KEY_FILEPATH` | | The file path of the private certificate for signing JWT tokens, if `TLS_KEY` is not defined. |
| `TLS_KEY_PASSPHRASE` | | The passphrase for decrypting the private certificate for signing JWT tokens. |

## Usage

### `getAllowedOriginMiddleware` middleware

The `getAllowedOriginMiddleware` middleware configures your Express.js application to send [CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) response headers. The middleware is configured using the `APPROVED_API_CALLERS` environment variable.

```javascript
import Express from 'express';
import AAA from '@advana/api-auth';

const app = Express();
app.use(AAA.getAllowedOriginMiddleware);
```

### `redisSession` middleware

The `redisSession` middleware configures your Express.js application to use the centralized Redis-backed storage for authenticated user sessions. The middleware is configured using the `REDIS_URL` (and `REDIS_USER`, `REDIS_PASSWORD`, and `TLS_CERT_CA` or `TLS_CERT_CA_FILEPATH`), `SECURE_SESSION`, `COOKIE_DOMAIN`, `EXPRESS_SESSION_SECRET`, and `EXPRESS_SESSION_MAX_AGE` environment variables.

```javascript
import Express from 'express';
import AAA from '@advana/api-auth';

const app = Express();
app.use(AAA.redisSession());
```

### `setupSaml`

The `setupSaml` function configures your Express.js application to use the Advana single sign-on (SSO) provider using SAML-based authentication. This is configured using the `SSO_DISABLED`, `APPROVED_API_CALLERS`, `PG_HOST`, `PG_USER`, `PG_PASSWORD`, `PG_UM_DB`, `AD_ENABLED`, `LDAP_URL`, `LDAP_CERT`, `LDAP_USERNAME`, `LDAP_PASSWORD`, `LDAP_USER_FOLDER_CN`, `SAML_ISSUER`, `SAML_CALLBACK_URL`, `SAML_ENTRYPOINT`, `SAML_LOGOUT_URL`, `SAML_LOGOUT_CALLBACK_URL`, and `SAML_CERT` environment variables.

This function also registers the following routes in your application:

* GET /login
* POST /login/callback
* GET /login/fail
* GET /logout
* POST /logout/callback
* GET /setUserSession

```javascript
import Express from 'express';
import AAA from '@advana/api-auth';

const app = Express();
AAA.setupSaml(app);
```

### `ensureAuthenticated` middleware

The `ensureAuthenticated` middleware configures your Express.js application to ensure the current user is authenticated via the centralized Redis-backed storage for authenticated user sessions. The middleware is configured using the `SSO_DISABLED` environment variable, but also requires the `redisSession` middleware to be configured and in use.

```javascript
import Express from 'express';
import AAA from '@advana/api-auth';

const app = Express();
app.use(AAA.redisSession());
app.use(AAA.ensureAuthenticated);
```

### `getToken` POST request handler

The `getToken` request handler responds to HTTP POST requests to the configured route (usually /api/auth/token) in your Express.js application with a JSON Web Token (JWT) to link the Redis-backed authenticated user session to your client application. The request handler is configured using the `TLS_KEY` or `TLS_KEY_FILEPATH`, and `TLS_PASSPHRASE` environment variables, but also requires the `redisSession` middleware to be configured and in use.

```javascript
import Express from 'express';
import AAA from '@advana/api-auth';

const app = Express();
app.use(AAA.redisSession());
app.post('/api/auth/token', AAA.getToken);
```

### `permCheck` middleware

The `permCheck` middleware configures your Express.js application to authorize the current user session against an array of permissions. If the user has any of the specified permissions - or the WebApp Super Admin or Tier 3 Support permissions - the middleware returns `next()`. Otherwise, the middleware sends an HTTP 403 error and prevents access to any routes in the chain. This middleware requires the `redisSession` middleware to be configured and in use.

```javascript
import Express from 'express';
import AAA from '@advana/api-auth';

const app = Express();
app.use(AAA.redisSession());

app.use((req, res, next) =>
  AAA.permCheck(req, res, next, [SPECIAL_PERMISSION])
);

// this route will not be served to the user unless he or she has
// the "SPECIAL_PERMISSION" permission.
app.get('/api/special/route', (req, res) => {
  specialRouteHandler(req, res);
});
```

### `fetchActiveDirectoryPermissions`

The `fetchActiveDirectoryPermissions` function returns an array of permissions from Active Directory based on the specified user ID (typically found in `req.session.user.id`, but the value can come from elsewhere). The Active Directory connection must be configured using the `LDAP_URL`, `LDAP_CERT`, `LDAP_USERNAME`, `LDAP_PASSWORD`, and `LDAP_USER_FOLDER_CN` environment variables.

```javascript
import Express from 'express';
import AAA from '@advana/api-auth';

const app = Express();
app.use(AAA.redisSession());

// please don't do this...
app.get('/example/route', (req, res, next) => {
  const permissions = AAA.fetchActiveDirectoryPermissions(req.session.user.id);
  return next();
});
```