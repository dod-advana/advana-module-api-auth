const fs = require('fs');
const RSAkeyDecrypt = require('ssh-key-decrypt');

/**
 * The log level for the api-auth library to use.
 * @since 2.6.0
 * @internal
 */
const API_AUTH_LOG_LEVEL = process.env.API_AUTH_LOG_LEVEL;

const PG_HOST = process.env.PG_UOT_HOST || process.env.PG_HOST;
const PG_DATABASE = process.env.PG_UM_DB;
const PG_USERNAME = process.env.PG_UOT_USER || process.env.PG_USER;
const PG_PASSWORD = process.env.PG_UOT_PASSWORD || process.env.PG_PASSWORD;

/**
 * Boolean flag indicating whether SSL/TLS should be used for connecting to
 * PostgreSQL. The default value is `true`.
 * @since 2.7.0
 * @internal
 */
const PG_SSL_REQUIRE = process.env.PG_SSL_REQUIRE !== 'false';

const SSO_DISABLED = process.env.DISABLE_SSO === 'true';

const readCert = (value, filePath) => {
	if (value) {
		return value.replace(/\\n/g, '\n');
	} else {
		// eslint-disable-next-line security/detect-non-literal-fs-filename
		return fs.readFileSync(filePath, 'ascii');
	}
};

const TLS_CERT_CA = readCert(
	process.env.TLS_CERT_CA,
	process.env.TLS_CERT_CA_FILEPATH
);

const TLS_KEY = readCert(process.env.TLS_KEY, process.env.TLS_KEY_FILEPATH);

const TLS_PRIVATE_KEY =
	'-----BEGIN RSA PRIVATE KEY-----\n' +
	RSAkeyDecrypt(TLS_KEY, process.env.TLS_KEY_PASSPHRASE, 'base64')
		.match(/.{1,64}/g)
		.join('\n') +
	'\n-----END RSA PRIVATE KEY-----';

module.exports = {
	API_AUTH_LOG_LEVEL,
	PG_DATABASE,
	PG_HOST,
	PG_PASSWORD,
	PG_SSL_REQUIRE,
	PG_USERNAME,
	SSO_DISABLED,
	TLS_CERT_CA,
	TLS_PRIVATE_KEY,
};
