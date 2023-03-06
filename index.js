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

const ldap = require('ldapjs');
const logger = require('@dod-advana/advana-logger');
const samlStrategy = require('./samlStrategy');
const AD = require('activedirectory2').promiseWrapper;

const SSO_DISABLED = process.env.DISABLE_SSO === 'true';
const IS_DECOUPLED = process.env.IS_DECOUPLED && process.env.IS_DECOUPLED === 'true'

const getMaxAge = () => {
	const MAX_MAX_AGE = 43200000; // 12 hours
	const MIN_MAX_AGE = 1800000; // 30 minutes
	const APP_DEFINED_MAX_AGE = parseInt(process.env.EXPRESS_SESSION_MAX_AGE);
	let MAX_AGE = MAX_MAX_AGE; // default to max

	if (APP_DEFINED_MAX_AGE) {
		// don't allow it to be set greater than MAX or lower than MIN
		MAX_AGE = Math.max(Math.min(APP_DEFINED_MAX_AGE, MAX_MAX_AGE), MIN_MAX_AGE);
	}

	return MAX_AGE;
}

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

	const MAX_AGE = getMaxAge();

	let secret = 'keyboard cat';
	if (process.env.EXPRESS_SESSION_SECRET){
		secret = process.env.EXPRESS_SESSION_SECRET?.includes('|') ? process.env.EXPRESS_SESSION_SECRET?.split('|') : JSON.parse(process.env.EXPRESS_SESSION_SECRET) || 'keyboard cat';
	}

	return session({
		store: new RedisStore(redisOptions),
		expires: new Date(Date.now() + MAX_AGE),
		secret: secret,
		resave: false,
		saveUninitialized: true,
		cookie: {
			maxAge: MAX_AGE,
			secure: process.env.SECURE_SESSION === 'true',
			httpOnly: true,
			...extraSessionOptions,
		},
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
		if (req.isAuthenticated()) {
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
			displayName: user?.displayname || adUser.displayName,
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

const updateLoginTime = async (req, res) => {
	let userid;
	if (SSO_DISABLED) {
		userid = req.get('SSL_CLIENT_S_DN_CN');
	} else {
		userid = req.user.id;
	}

	let dbClient = await pool.connect();

	try{
		let loginTimeSQL = 'UPDATE users SET lastlogin=NOW() WHERE username=$1';
		await dbClient.query(loginTimeSQL, [userid]);
	} catch (err) {
		logger.error(err)
	} finally {
		dbClient.release();
	}
}

const setUserSession = async (req, res) => {
	try {
		req.session.user = await fetchUserInfo(req.user.id, req.user?.cn || req.get('x-env-ssl_client_certificate'));
		req.session.user.session_id = req.sessionID;
		logger.info(`Setting user session: user - ${req.user.id}, session id - ${req.sessionID}, IP - ${req.ip}`)
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

	passport.use(samlStrategy);

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

	app.get('/logout', function(req, res) {
		if (req.user == null) {
		  return res.redirect('/');
		}
		samlStrategy.logout(req, function(err, uri) {
			if(!err){
				return res.redirect("/login")
			}
			if(err){
				logger.info(err)
			}
		});
	});

	app.post('/logout/callback', function(req, res){
		req.logout();
		res.redirect('/login');
	});

	app.get(
		'/api/setUserSession',
		(req, res, next) => {
			if (req.isAuthenticated()) {
				updateLoginTime(req, res)
				return next();
			}
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
	getMaxAge
};
