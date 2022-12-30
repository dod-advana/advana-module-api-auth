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

const ldap = require('ldapjs');
const logger = require('advana-logger');
const AD = require('activedirectory2').promiseWrapper;

const SAML_CONFIGS = require('./samlConfigs');

const SSO_DISABLED = process.env.DISABLE_SSO === 'true';

const retry_strategy = (options) => {
	if (options.attempt > 75) {
		return new Error('Redis connection attempts timed out');
	}

	// square number of retries to get an exponential curve of retries
	// return number of milleseconds to wait before retrying again
	logger.info('Redis attempting to retry connection. Try number: ', options.attempt);
	return options.attempt * options.attempt * 100;
};
const client = redis.createClient({ url: process.env.REDIS_URL, retry_strategy: retry_strategy });

const pool = new Pool({
	user: process.env.PG_USER,
	password: process.env.PG_PASSWORD,
	host: process.env.PG_HOST,
	database: process.env.PG_UM_DB,
});

let keyFileData;
if (process.env.TLS_KEY) {
	keyFileData = process.env.TLS_KEY.replace(/\\n/g, '\n');
} else {
	keyFileData = fs.readFileSync(process.env.TLS_KEY_FILEPATH, 'ascii');
}

const private_key =
	'-----BEGIN RSA PRIVATE KEY-----\n' +
	RSAkeyDecrypt(keyFileData, process.env.TLS_KEY_PASSPHRASE, 'base64')
		.match(/.{1,64}/g)
		.join('\n') +
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
		logger.error(e);
	}

	res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
	res.header(
		'Access-Control-Allow-Headers',
		'Accept, Origin, Content-Type, Authorization, Content-Length, X-Requested-With, Accept-Language, SSL_CLIENT_S_DN_CN, X-UA-SIGNATURE, permissions'
	);
	res.header('Access-Control-Allow-Credentials', true);
	res.header('Access-Control-Expose-Headers', 'Content-Disposition');
	// intercepts OPTIONS method
	if (req.method === 'OPTIONS') {
		res.sendStatus(200);
	} else {
		next();
	}
};
const redisSession = () => {
	let redisOptions = {
		host: process.env.REDIS_URL,
		port: '6379',
		client: client,
	};

	let extraSessionOptions = {};

	if (process.env.COOKIE_DOMAIN) {
		extraSessionOptions.domain = process.env.COOKIE_DOMAIN;
	}

	return session({
		store: new RedisStore(redisOptions),
		expires: new Date(Date.now() + 43200000),
		secret: JSON.parse(process.env.EXPRESS_SESSION_SECRET),
		resave: false,
		saveUninitialized: true,
		cookie: {
			maxAge: 43200000,
			secure: process.env.SECURE_SESSION === 'true',
			httpOnly: true,
			...extraSessionOptions,
		},
	});
};

const ensureAuthenticated = async (req, res, next) => {
	if (req.isAuthenticated()) {
		if (req.session.user.disabled) return res.status(403).send();

		return next();
	} else if (SSO_DISABLED) {
		req.session.user = await fetchUserInfo(req);
		next();
	} else {
		return res.status(401).send();
	}
};

const fetchUserInfo = async (req) => {
	let userid;

	if (SSO_DISABLED) {
		userid = req.get('SSL_CLIENT_S_DN_CN');
	} else {
		userid = req.user.id;
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

	try {
		let user = await dbClient.query(userSQL, [userid]);
		user = user.rows[0] || {};

		let adUser = {};

		if (process.env.AD_ENABLED === 'true') {
			const t0 = new Date().getTime();
			adUser = await fetchActiveDirectoryUserInfo(userid);
			const t1 = new Date().getTime();
			console.log(`Call to fetchActiveDirectoryUserInfo took ${(t1 - t0) / 1000} seconds.`);
		}

		// Create a new user if they don't exist in the database
		let perms = [];
		if (!user.id) {
			const addNewUserSQL = `
				INSERT INTO users (username, displayname, disabled, "createdAt", "updatedAt", email)
				VALUES ($1, $2, $3, $4, $5, $6);
			`;
			try {
				await dbClient.query(addNewUserSQL, [
					userid,
					adUser?.displayName || '',
					false,
					new Date(),
					new Date(),
					adUser?.mail || '',
				]);
			} catch (e) {
				logger.error(e);
			}
		} else {
			perms = await dbClient.query(permsSQL, [userid]);
			perms = perms.rows.map(({ name }) => name);
		}

		return {
			id: userid,
			displayName: req?.user?.displayName || user.displayname || adUser.displayName,
			perms: perms.concat(adUser?.perms || [], !SSO_DISABLED ? req?.user?.perms : []),
			sandboxId: user.sandbox_id || adUser.sandboxId,
			disabled: user.disabled || adUser.disabled,
			cn: req?.user?.cn || adUser.cn,
			email: req?.user?.email || adUser.email,
			retrievedADPerms: adUser?.perms?.length > 0,
		};
	} catch (err) {
		console.error(err);
		return {};
	} finally {
		dbClient.release();
	}
};

const fetchActiveDirectoryUserInfo = async (userId) => {
	try {
		const config = {
			url: process.env.LDAP_URL,
			tlsOptions: {
				rejectUnauthorized: false,
				ca: [process.env.LDAP_CERT.replace(/\\n/g, '\n')],
			},
			baseDN: process.env.LDAP_USER_FOLDER_CN,
			username: process.env.LDAP_USERNAME,
			password: process.env.LDAP_PASSWORD,
		};

		const ad = new AD(config);

		const userObj = await ad.findUser(userId.split('@')[0]);
		if (!userObj) {
			console.log('User: ' + userId + ' not found.');
			return {};
		}

		const groups = await ad.getGroupMembershipForUser(userId.split('@')[0]);
		const groupPerms = [];
		if (!groups) {
			console.log('User: ' + userId + ' not found.');
		} else {
			groups.forEach((group) => {
				groupPerms.push(group.cn);
			});
		}

		return {
			id: userObj.sAMAccountName,
			displayName: userObj.displayName,
			perms: groupPerms,
			sandboxId: 1,
			cn: userObj.cn,
			dn: userObj.dn,
			disabled: false,
			email: userObj.mail,
		};
	} catch (err) {
		logger.error(err);
		return {};
	}
};

const fetchActiveDirectoryPermissions = async (userId) => {
	try {
		const config = {
			url: process.env.LDAP_URL,
			tlsOptions: {
				rejectUnauthorized: false,
				ca: [process.env.LDAP_CERT.replace(/\\n/g, '\n')],
			},
			baseDN: process.env.LDAP_USER_FOLDER_CN,
			username: process.env.LDAP_USERNAME,
			password: process.env.LDAP_PASSWORD,
		};

		const ad = new AD(config);

		const groups = await ad.getGroupMembershipForUser(userId.split('@')[0]);
		const groupPerms = [];
		if (!groups) {
			console.log('User: ' + userId + ' not found.');
		} else {
			groups.forEach((group) => {
				groupPerms.push(group.cn);
			});
		}

		return groupPerms;
	} catch (err) {
		logger.error(err);
		return [];
	}
};

// THE CODE BELOW IS GENERAL FUNCTIONS TO ADD/REMOVE USERS TO AND FROM ACTIVE DIRECTORY GROUPS. UX DESIGN REQUIRED BEFORE FUCTIONS FINISHED
/*use this to add user to group*/
function addUserToGroup(groupname, userToAddDn) {
	const ldapclient = ldap.createClient({
		url: process.env.LDAP_URL,
	});
	const change = new ldap.Change({
		operation: 'add',
		modification: {
			member: [userToAddDn],
		},
	});

	ldapclient.modify(groupname, change, function (err) {
		if (err) {
			console.log('err in add user in a group ' + err);
		} else {
			console.log('added user in a group');
		}
	});
}

/*use this to remove user from group*/
function removeUserFromGroup(groupname, userToRemoveDn) {
	const ldapclient = ldap.createClient({
		url: process.env.LDAP_URL,
	});
	const change = new ldap.Change({
		operation: 'delete',
		modification: {
			member: [userToRemoveDn],
		},
	});

	ldapclient.modify(groupname, change, function (err) {
		if (err) {
			console.log('err in remove user from a group ' + err);
		} else {
			console.log('removed user from a group');
		}
	});
}

const hasPerm = (desiredPermission = '', permissions = []) => {
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
		let permissions = req.session.user && req.session.user.perms ? req.session.user.perms : [];
		for (let p of permissionToCheckFor) {
			if (hasPerm(p, permissions)) return next();
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
		req.session.user = await fetchUserInfo(req);
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
};

const setupSaml = (app) => {
	passport.serializeUser((user, done) => {
		done(null, user);
	});
	passport.deserializeUser((user, done) => {
		done(null, user);
	});

	passport.use(
		new SamlStrategy(SAML_CONFIGS.SAML_OBJECT, function (profile, done) {
			const perms = new Set();
			profile.getAssertion().Assertion.AttributeStatement.forEach((attributeStatement) => {
				attributeStatement['Attribute'].forEach((attr) => {
					if (attr['$']['Name'] === SAML_CONFIGS.SAML_CLAIM_PERMS) {
						attr['AttributeValue'].forEach((attrValue) => {
							perms.add(attrValue['_']);
						});
					}
				});
			});
			return done(null, {
				id: profile[SAML_CONFIGS.SAML_CLAIM_ID],
				email: profile[SAML_CONFIGS.SAML_CLAIM_EMAIL],
				displayName: profile[SAML_CONFIGS.SAML_CLAIM_DISPLAYNAME],
				perms: Array.from(perms),
				cn: profile[SAML_CONFIGS.SAML_CLAIM_CN],
			});
		})
	);

	app.use(passport.initialize());
	app.use(passport.session());

	app.get(
		'/login',
		(req, res, next) => {
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
			passport.authenticate('saml', { failureRedirect: '/login/fail' })(req, res, next);
		},
		(req, res) => {
			SSORedirect(req, res);
		}
	);

	app.post('/login/callback', passport.authenticate('saml', { failureRedirect: '/login/fail' }), (_req, res) => {
		res.redirect('/api/setUserSession');
	});

	app.get('/login/fail', (_req, res) => {
		res.status(401).send('Login failed');
	});

	app.get(
		'/api/setUserSession',
		(req, res, next) => {
			if (req.isAuthenticated()) return next();
			else return res.redirect('/login');
		},
		setUserSession
	);
};

// END SAML PORTION

module.exports = {
	getAllowedOriginMiddleware,
	getToken,
	ensureAuthenticated,
	permCheck,
	redisSession,
	setUserSession,
	setupSaml,
	fetchActiveDirectoryPermissions,
};
