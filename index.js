const fs = require('fs');
const CryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');
const RSAkeyDecrypt = require('ssh-key-decrypt');
const secureRandom = require('secure-random');

const { Pool } = require('pg');

const session = require('express-session');
const redis = require('redis');
const RedisStore = require('connect-redis')(session);

const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;


const SAML_CONFIGS = require('./samlConfigs');

const client = redis.createClient(process.env.REDIS_URL);
const pool = new Pool({
	user: process.env.PG_USER,
	password: process.env.PG_PASSWORD,
	host: process.env.PG_HOST,
	database: process.env.PG_UM_DB
});

const keyFileData = fs.readFileSync(process.env.TLS_KEY_FILEPATH, 'ascii');
const private_key = '-----BEGIN RSA PRIVATE KEY-----\n' +
	(RSAkeyDecrypt(keyFileData, process.env.TLS_KEY_PASSPHRASE, 'base64')).match(/.{1,64}/g).join('\n') +
	'\n-----END RSA PRIVATE KEY-----';

const getToken = (req, res) => {
	try {
		let csrfHash = CryptoJS.SHA256(secureRandom(10)).toString(CryptoJS.enc.Hex);
		let jwtClaims = req.session.user;
		jwtClaims['csrf-token'] = csrfHash;

		let token = jwt.sign(jwtClaims, private_key, { algorithm: 'RS256' });

		res.status(200).send({ token });
	} catch (error) {
		console.info(error);
		res.status(400).send();
	}
};

const getAllowedOriginMiddleware = (req, res, next) => {
	try {
		if (req && req.headers && process.env.APPROVED_API_CALLERS.split(',').includes(req.headers.origin)) {
			res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
		}
	} catch (e) {
		//this error happens in docker where origin is undefined
		logger.error(e);
	}

	res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
	res.header('Access-Control-Allow-Headers', 'Accept, Origin, Content-Type, Authorization, Content-Length, X-Requested-With, Accept-Language, SSL_CLIENT_S_DN_CN, X-UA-SIGNATURE, permissions');
	res.header('Access-Control-Allow-Credentials', true);
	res.header('Access-Control-Expose-Headers', 'Content-Disposition');
	// intercepts OPTIONS method
	if (req.method === 'OPTIONS') {
		res.sendStatus(200);
	} else {
		next();
	}
}
const redisSession = () => {
	let redisOptions = {
		host: process.env.REDIS_URL,
		port: '6379',
		client: client
	};

	let extraSessionOptions = {};

	if (process.env.COOKIE_DOMAIN) {
		extraSessionOptions.domain = process.env.COOKIE_DOMAIN;
	}

	return session({
		store: new RedisStore(redisOptions),
		expires: new Date(Date.now() + (43200000)),
		secret: 'keyboard cat',
		resave: false,
		saveUninitialized: true,
		cookie: { maxAge: 43200000, secure: process.env.SECURE_SESSION, httpOnly: true, ...extraSessionOptions }
	});
};

const ensureAuthenticated = async (req, res, next) => {
	if (req.isAuthenticated()) {
		if (req.session.user.disabled)
			return res.status(403).send();

		return next();
	} else 
	if (process.env.DISABLE_SSO) {
		req.session.user = await fetchUserInfo(req.get('SSL_CLIENT_S_DN_CN'));
		next();
	} else {
		return res.status(401).send();
	}
};

const fetchUserInfo = async (userid) => {
	let client = await pool.connect();
	let userSQL = `SELECT * FROM users WHERE username = $1`;

	let permsSQL = `
		SELECT distinct(p.name)
		FROM users u
		LEFT JOIN userroles ur on ur.userid=u.id
		LEFT JOIN roles r on ur.roleid=r.id
		LEFT JOIN roleperms rp on r.id = rp.roleid
		LEFT JOIN permissions p on p.id = rp.permissionid
		WHERE username = $1 and p.name is not null
	`;

	try {
		let user = await client.query(userSQL, [userid]);
		user = user.rows[0] || {};
		let perms = await client.query(permsSQL, [userid]);
		perms = perms.rows.map(({ name }) => name);

		return {
			id: user.username,
			displayName: user.displayname,
			perms: perms,
			sandboxId: user.sandbox_id,
			disabled: user.disabled
		};

	} catch (err) {
		console.error(err);
		return {};
	} finally {
		client.release();
	}
};


// SAML PORTION


const setUserSession = async (req, res) => {
	try {
		req.session.user = fetchUserInfo(req.user.id);
		req.session.user.session_id = req.sessionID;
		SSORedirect(req, res);
	} catch (err) {
		console.error(err);
	}
};

const SSORedirect = (req, res) => {
	const alternateOrigin = req.session.AlternateSsoOrigin;
	console.log(alternateOrigin)
	if (alternateOrigin) {
		req.session.AlternateSsoOrigin = undefined;
		return res.redirect(alternateOrigin + '/');
	} else {
		return res.redirect('/');
	}
}

const setupSaml = (app) => {

	passport.serializeUser((user, done) => { done(null, user); });
	passport.deserializeUser((user, done) => { done(null, user); });

	passport.use(new SamlStrategy(
		SAML_CONFIGS.SAML_OBJECT,
		function (profile, done) {
			return done(null, {
				id: profile[SAML_CONFIGS.SAML_CLAIM_ID],
				email: profile[SAML_CONFIGS.SAML_CLAIM_EMAIL],
				displayName: profile[SAML_CONFIGS.SAML_CLAIM_DISPLAYNAME],
				perms: profile[SAML_CONFIGS.SAML_CLAIM_PERMS]
			});
		}));

	app.use(passport.initialize());
	app.use(passport.session());

	app.get('/login', (req, res, next) => {
		const referer = req.get('Referer');
		if (referer) {
			try {
				const parsedReferer = new URL(referer);
				const refererOrigin = parsedReferer.origin.replace('www.', '');
				const approvedClients = process.env.APPROVED_API_CALLERS.split(',');
				// store referer origin in session in order to redirect to correct domain after SAML auth
				if (approvedClients.includes(refererOrigin) && refererOrigin !== approvedClients[0]) {
					req.session.AlternateSsoOrigin = refererOrigin;
				}
			} catch (error) {
				logger.info(error);
			}
		}
		passport.authenticate('saml', { failureRedirect: '/login/fail' })(req, res, next);
	}, (req, res) => { SSORedirect(req, res); });

	app.post('/login/callback',
		passport.authenticate('saml', { failureRedirect: '/login/fail' }),
		(req, res) => { res.redirect('/api/setUserSession'); }
	);

	app.get('/login/fail',
		(req, res) => { res.status(401).send('Login failed'); }
	);


	app.get('/api/setUserSession', (req, res, next) => {
		if (req.isAuthenticated())
			return next();
		else
			return res.redirect('/login');
	}, setUserSession);

}

// END SAML PORTION

module.exports = {
	getAllowedOriginMiddleware,
	getToken,
	ensureAuthenticated,
	redisSession,
	setUserSession,
	setupSaml
};