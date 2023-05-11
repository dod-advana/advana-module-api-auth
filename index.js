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
const logger = require('@dod-advana/advana-logger');

const IS_DECOUPLED = process.env.IS_DECOUPLED && process.env.IS_DECOUPLED === 'true'

const SAML_CONFIGS = require('./samlConfigs');
const retry_strategy = (options) => {
	if(options.attempt > 75){
		return new Error('Redis connection attempts timed out');
	}

	// square number of retries to get an exponential curve of retries
	// return number of milleseconds to wait before retrying again
	logger.info('Redis attempting to retry connection. Try number: ', options.attempt);
	return options.attempt * options.attempt *100;
}
const client = redis.createClient({url: process.env.REDIS_URL, retry_strategy: retry_strategy});

const pool = new Pool({
	user: process.env.PG_USER,
	password: process.env.PG_PASSWORD,
	host: process.env.PG_HOST,
	database: process.env.PG_UM_DB
});

let keyFileData;
if (process.env.TLS_KEY) {
	keyFileData = process.env.TLS_KEY.replace(/\\n/g, '\n');
} else {
	keyFileData = fs.readFileSync(process.env.TLS_KEY_FILEPATH, 'ascii');
}

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
		if (req && req.headers && process.env.APPROVED_API_CALLERS.split(' ').includes(req.hostname)) {
			res.setHeader('Access-Control-Allow-Origin', req.hostname);
		} else if (req && req.headers && process.env.APPROVED_API_CALLERS.split(' ').includes(req.headers.origin)) {
			res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
		}
	} catch (e) {
		//this error happens in docker where origin is undefined
		if (process.env.REQUEST_ORIGIN_ALLOWED) {
			res.setHeader('Access-Control-Allow-Origin', process.env.REQUEST_ORIGIN_ALLOWED);
		} else {
			logger.error(e);
			res.setHeader('Access-Control-Allow-Origin', '*.advana.data.mil');
		}
	}

	res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
	res.header('Access-Control-Allow-Headers', 'Accept, Origin, Content-Type, Authorization, Content-Length, X-Requested-With, Accept-Language, SSL_CLIENT_S_DN_CN, X-UA-SIGNATURE, permissions');
	res.header('Access-Control-Allow-Credentials', true);
	res.header('Access-Control-Expose-Headers', 'Content-Disposition');
	// intercepts OPTIONS method
	if (req.method === 'OPTIONS') {
		res.sendStatus(200);
	} else {
		if (!req.permissions) {
			req.permissions = [];
		}
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
		secret: process.env.EXPRESS_SESSION_SECRET?.split('|') || 'keyboard cat',
		resave: false,
		saveUninitialized: true,
		cookie: { maxAge: 43200000, secure: process.env.SECURE_SESSION === 'true', httpOnly: true, ...extraSessionOptions }
	});
};

const ensureAuthenticated = async (req, res, next) => {
	// If Decoupled then we need to make the userId off of the cn then create the req.user objects
	if (IS_DECOUPLED)  {
		let cn = req.get('x-env-ssl_client_certificate');
		cn = cn?.split('=') || [];
		if (cn.length > 1) {
			cn = cn[1];
		} else {
			cn = cn[0];
		}
		if (!cn) {
			if (req.get('SSL_CLIENT_S_DN_CN')==='ml-api'){
				next();
			} else {
				return res.status(403).send('Unauthorized');
			}
		} else {
			const cnSplit = cn.split('.');
			const userID = `${cnSplit[cnSplit.length - 1]}@mil`;

			req.user = await fetchUserInfo(userID, cn);
			req.session.user = req.user;
			req.session.user.session_id = req.sessionID;
			req.headers['SSL_CLIENT_S_DN_CN'] = userID;
			next();
		}
	} else {
		console.log('ensure authenticated for a coupled app req for url: ', req.originalUrl)
		console.log(`req.user.id is ${req?.user?.id}`);
		if (req.isAuthenticated()) {
			console.log(`req is authenticated with session id ${req.sessionID}`);
			if (!req.user.cn || !req.user.perms) {
				// User has been authenticated in another app that does not have the CN SAML values
				if (req.get('x-env-ssl_client_certificate')) {
					req.user.cn = req.get('x-env-ssl_client_certificate');
				} else {
					if (req.user.displayName && req.user.id) {
						const first = req.user.displayName.split(' ')[0];
						const last = req.user.displayName.split(' ')[1];
						req.user.cn = `${first}.${last}.MI.${req.user.id}`;
					} else if (req.user.id) {
						req.user.cn = `FIRST.LAST.MI.${req.user.id}`;
					} else {
						req.user.cn = 'FIRST.LAST.MI.1234567890@mil';
					}
					req.user = await fetchUserInfo(req.user.id, req.user.cn);
				}
				req.session.user = req.user;
				req.session.user.session_id = req.sessionID;
			}
			return next();
		} else if (process.env.DISABLE_SSO === 'true') {
			req.session.user = await fetchUserInfo(req.get('SSL_CLIENT_S_DN_CN'), req.get('x-env-ssl_client_certificate'));

			if (!req.session.user) {
				return res.status(403).send();
			} else {
				next();
			}
		} else {
			console.log('req not authenticated and SSO enabled -- user not authorized');
			console.log(`user id ${req?.user?.id} user cn ${req?.user?.cn} session id ${req?.sessionID}`);
			return res.status(401).send();
		}
	}
};

const fetchUserInfo = async (userid, cn) => {

	if (!userid && !cn) {
		return false;
	}

	let dbClient = await pool.connect();
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

	let user;
	let perms = [];
	let firstName = 'First';
	let lastName = 'Last';
	let displayName = 'First Last';
	try {
		user = await dbClient.query(userSQL, [userid]);

		user = user.rows[0];

		perms = await dbClient.query(permsSQL, [userid]);
		perms = perms.rows.map(({ name }) => name);
		if (cn) {
			firstName = cn.split('.')[1];
			lastName = cn.split('.')[0];
		}
		displayName = user?.displayname || `${firstName} ${lastName}`;
		return {
			id: user?.username || userid,
			displayName: displayName,
			perms: perms,
			sandboxId: user?.sandbox_id || 1,
			disabled: user?.disabled || false,
			cn: cn,
			firstName: firstName,
			lastName: lastName
		};
	} catch (err) {
		console.error(err);
		return {};
	} finally {
		dbClient.release();
	}


};


const hasPerm = (desiredPermission = "", permissions = []) => {
	if (permissions.length > 0) {
		for (let perm of permissions) {
			if (
				perm.toUpperCase() === desiredPermission.toUpperCase() ||
				perm.toUpperCase() === 'WEBAPP SUPER ADMIN' ||
				perm.toUpperCase() === 'TIER 3 SUPPORT'
			) {
				return true;
			}
		}
	}
	return false;
};

const permCheck = (req, res, next, permissionToCheckFor = []) => {
	try {
		let permissions = (req.session.user && req.session.user.perms) ? req.session.user.perms : [];
		for (let p of permissionToCheckFor) {
			if (hasPerm(p, permissions))
				return next();
		}
	} catch (err) {
		console.error('Error reading request permissions.');
		console.error(err);
		return res.status(403).send();
	}
	return res.status(403).send();
};

// SAML PORTION


const setUserSession = async (req, res) => {
	try {
		req.session.user = await fetchUserInfo(req.user.id, req.user?.cn || req.get('x-env-ssl_client_certificate'));
		req.session.user.session_id = req.sessionID;
		SSORedirect(req, res);
	} catch (err) {
		console.error(err);
	}
};

const SSORedirect = (req, res) => {
	const alternateOrigin = req.session.AlternateSsoOrigin;
	if (alternateOrigin) {
		req.session.AlternateSsoOrigin = undefined;
		return res.redirect(alternateOrigin + '/');
	} else {
		return res.redirect('/');
	}
}

const setupSaml = (app) => {

	if (!IS_DECOUPLED) {
		passport.serializeUser((user, done) => {
			console.log(`serialize user:  ${user} with id ${user?.id}`);
			done(null, user);
		});
		passport.deserializeUser((user, done) => {
			console.log(`deserialize user:  ${user} with id ${user?.id}`);
			try {
				done(null, user);
			} catch(err) {
				console.log('deserialize user error')
				console.log(err)
				console.log(err.message);
			}
		});

		passport.use(new SamlStrategy(
			SAML_CONFIGS.SAML_OBJECT,
			function (profile, done) {
				return done(null, {
					id: profile[SAML_CONFIGS.SAML_CLAIM_ID],
					email: profile[SAML_CONFIGS.SAML_CLAIM_EMAIL],
					displayName: profile[SAML_CONFIGS.SAML_CLAIM_DISPLAYNAME],
					perms: profile[SAML_CONFIGS.SAML_CLAIM_PERMS],
					cn: profile[SAML_CONFIGS.SAML_CLAIM_CN],
					firstName: profile[SAML_CONFIGS.SAML_CLAIM_FIRST_NAME],
					lastName: profile[SAML_CONFIGS.SAML_CLAIM_LAST_NAME]
				});
			}));

		app.use((req, res, next) => {
			console.log(`before passport initialize/session,
				req.originalUrl ${req.originalUrl}
				req.sessionID ${req.sessionID}
				req.session.user ${user} with id ${user?.id}
				req.session.passport ${req?.session?.passport} 
				req.session.passport.user ${req?.session?.passport?.user}
				req.session.passport.user.id ${req?.session?.passport?.user?.id}
				res get headers ${JSON.stringify(res.getHeaders())}`
			)
			next();
		});

		app.use(passport.initialize());
		app.use((req, res, next) => {
			console.log(`between passport initialize/session,
				req.originalUrl ${req.originalUrl}
				req.sessionID ${req.sessionID}
				req.session.user ${user} with id ${user?.id}
				req.session.passport ${req?.session?.passport} 
				req.session.passport.user ${req?.session?.passport?.user}
				req.session.passport.user.id ${req?.session?.passport?.user?.id}
				res get headers ${JSON.stringify(res.getHeaders())}`
			)
			next();
		});
		app.use(passport.session());

		app.use((req, res, next) => {
			console.log(`after passport initialize/session,
				req.originalUrl ${req.originalUrl}
				req.sessionID ${req.sessionID}
				req.session.user ${user} with id ${user?.id}
				req.session.passport ${req?.session?.passport} 
				req.session.passport.user ${req?.session?.passport?.user}
				req.session.passport.user.id ${req?.session?.passport?.user?.id}
				res get headers ${JSON.stringify(res.getHeaders())}`
			)
			next();
		});

		app.get('/login', (req, res, next) => {
			const referer = req.get('Referer');
			if (referer) {
				try {
					const parsedReferer = new URL(referer);
					const refererOrigin = parsedReferer.origin.replace('www.', '');
					const approvedClients = process.env.APPROVED_API_CALLERS.split(' ');
					// store referer origin in session in order to redirect to correct domain after SAML auth
					if (approvedClients.includes(refererOrigin) && refererOrigin !== approvedClients[0]) {
						req.session.AlternateSsoOrigin = refererOrigin;
					}
				} catch (error) {
					logger.info(error);
				}
			}
			passport.authenticate('saml', {failureRedirect: '/login/fail'})(req, res, next);
		}, (req, res) => {
			SSORedirect(req, res);
		});

		app.post('/login/callback',
			passport.authenticate('saml', {failureRedirect: '/login/fail'}),
			(req, res) => {
				return res.redirect('/api/setUserSession');
			}
		);

		app.get('/login/fail',
			(req, res) => {
				return res.status(401).send('Login failed');
			}
		);


		app.get('/api/setUserSession', (req, res, next) => {
			if (req.isAuthenticated())
				return next();
			else
				return res.redirect('/login');
		}, setUserSession);
	}

}

// END SAML PORTION

module.exports = {
	getAllowedOriginMiddleware,
	getToken,
	ensureAuthenticated,
	permCheck,
	redisSession,
	setUserSession,
	setupSaml
};