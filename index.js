const CryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');
const secureRandom = require('secure-random');
const { Pool } = require('pg');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const passport = require('passport');
const ldap = require('ldapjs');
const AD = require('activedirectory2').promiseWrapper;

const SSO_DISABLED = process.env.DISABLE_SSO === 'true';
const IS_DECOUPLED = process.env.IS_DECOUPLED && process.env.IS_DECOUPLED === 'true';

const {
	createRedisClient,
	exponentialBackoffReconnect,
} = require('@advana/redis-client');

const env = require('./environment');
const {
	createLoggingContext,
	getRequestLogger,
	moduleLogger,
} = require('./moduleLogger');
const samlStrategy = require('./samlStrategy');

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
};

const pool = new Pool({
	host: env.PG_HOST,
	database: env.PG_DATABASE,
	ssl: env.PG_SSL_REQUIRE ? { ca: env.TLS_CERT_CA } : null,
	user: env.PG_USERNAME,
	password: env.PG_PASSWORD,
	application_name: `@advana/api-auth`,
});

if (!env.PG_SSL_REQUIRE) {
	moduleLogger.warn(
		`SSL disabled for PostgreSQL '${env.PG_DATABASE}' database connection`
	);
} else {
	moduleLogger.trace(
		`connected to PostgreSQL '${env.PG_DATABASE}' database via SSL`
	);
}

const generateToken = (claims) => {
	claims['csrf-token'] = CryptoJS.SHA256(secureRandom(10)).toString(
		CryptoJS.enc.Hex
	);
	return jwt.sign(claims, env.TLS_PRIVATE_KEY, { algorithm: 'RS256' });
};

const getToken = (req, res) => {
	const requestLogger = getRequestLogger(req);
	const loggingContext = createLoggingContext(req);

	try {
		if (req.method === 'POST' && !!req.body?.consent) {
			req.session.consent = req.body.consent;
			req.session.user.consent = req.body.consent;
		}
		const token = generateToken(req.session.user);
		res.status(200).send({ token });
	} catch (err) {
		requestLogger.error({ err, ...loggingContext });
		res.sendStatus(400);
	}
};

const getAllowedOriginMiddleware = (req, res, next) => {
	const requestLogger = getRequestLogger(req);
	const loggingContext = createLoggingContext(req);

	try {
		if (
			req &&
			req.headers &&
			process.env.APPROVED_API_CALLERS.split(' ').includes(req.hostname)
		) {
			res.setHeader('Access-Control-Allow-Origin', req.hostname);
		} else if (
			req &&
			req.headers &&
			process.env.APPROVED_API_CALLERS.split(' ').includes(req.headers.origin)
		) {
			res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
		}
	} catch (err) {
		//this error happens in docker where origin is undefined
		requestLogger.error({ err, ...loggingContext });
	}

	res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
	res.header(
		'Access-Control-Allow-Headers',
		'Accept, Origin, Content-Encoding, Content-Type, Authorization, Content-Length, X-Requested-With, Accept-Language, SSL_CLIENT_S_DN_CN, X-UA-SIGNATURE, permissions'
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

const redisClient = createRedisClient({
	name: '@advana/api-auth',
	socket: {
		reconnectStrategy: exponentialBackoffReconnect,
	},
});

const redisSession = () => {
	const secureSession = process.env.SECURE_SESSION.toLowerCase() === 'true';
	const sessionCookie = {
		maxAge: getMaxAge(),
		sameSite: secureSession ? 'none' : 'lax',
		secure: secureSession,
		httpOnly: true,
	};
	if (process.env.COOKIE_DOMAIN) {
		sessionCookie.domain = process.env.COOKIE_DOMAIN;
	}

	redisClient.connect();

	return session({
		store: new RedisStore({ client: redisClient }),
		secret: JSON.parse(process.env.EXPRESS_SESSION_SECRET),
		resave: false,
		saveUninitialized: true,
		cookie: sessionCookie,
	});
};

/*
const ensureAuthenticated = async (req, res, next) => {
	// If Decoupled then we need to make the userId off of the cn then create the req.user objects
	if (IS_DECOUPLED)  {
		if (!req?.session?.user || !req?.session?.user?.session_id) {
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
					req.user = await fetchUserInfo(req.user.id, req.user.cn, req?.user?.perms);
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
*/

const ensureAuthenticated = async (req, res, next) => {
	const requestLogger = getRequestLogger(req);
	const loggingContext = createLoggingContext(req);
	
	// If Decoupled then we need to make the userId off of the cn then create the req.user objects
	if (IS_DECOUPLED)  {
		if (!req?.session?.user || !req?.session?.user?.session_id) {
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
				const modifiedReq = {user: {}, ...req};
				modifiedReq.user.id = userID;
				modifiedReq.user.cn = cn;

				req.user = await fetchUserInfo(modifiedReq);
				req.session.user = req.user;
				req.session.user.session_id = req.sessionID;
				req.headers['SSL_CLIENT_S_DN_CN'] = userID;
				next();
			}
		} else {
			next();
		}
	} else if (!env.SSO_DISABLED && req.isAuthenticated()) {
		if (req.session?.user?.disabled) {
			requestLogger.warn(loggingContext, 'not authenticated: user disabled');
			return res.status(403).send();
		}
		requestLogger.trace(loggingContext, 'authenticated');
		return next();
	} else if (env.SSO_DISABLED) {
		req.session.user = await fetchUserInfo(req);
		requestLogger.trace(loggingContext, 'authenticated');
		return next();
	} else {
		requestLogger.warn(loggingContext, 'not authenticated');
		return res.status(401).send();
	}
};

const fetchUserInfo = async (req) => {
	const requestLogger = getRequestLogger(req);
	const loggingContext = createLoggingContext(req);

	let userid;

	if (IS_DECOUPLED) {
		userid = req.user.id;
	} else if (env.SSO_DISABLED && req.user.id) {
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
			requestLogger.trace(
				loggingContext,
				`Call to fetchActiveDirectoryUserInfo took ${(t1 - t0) / 1000} seconds.`
			);
		}

		let cn = req?.user?.cn || adUser.cn;
		let displayName = getDisplayName(req, user, adUser, cn);

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
					displayName,
					false,
					new Date(),
					new Date(),
					adUser?.mail || '',
				]);
			} catch (err) {
				requestLogger.error({ err, ...loggingContext });
			}
		} else {
			if (!user.displayName) {
				// user object in postgres has a blank display name; update it
				if (displayName) {
					await dbClient.query(
						`UPDATE users SET displayname = $1 WHERE username = $2`,
						[displayName, userid]
					);
				} else {
					// what to do? we can't get the display name from anywhere...
				}
			}

			perms = await dbClient.query(permsSQL, [userid]);
			perms = perms.rows.map(({ name }) => name);
		}

		return {
			id: userid,
			displayName,
			perms: perms.concat(
				adUser?.perms || [],
				!env.SSO_DISABLED ? req?.user?.perms : []
			),
			sandboxId: user.sandbox_id || adUser.sandboxId,
			disabled: user.disabled || adUser.disabled,
			cn,
			email: req?.user?.email || adUser.email,
			retrievedADPerms: adUser?.perms?.length > 0,
			consent: req?.session?.consent,
		};
	} catch (err) {
		requestLogger.error({ err, ...loggingContext });
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
			moduleLogger.warn('user: ' + userId + ' not found.');
			return {};
		}

		const groups = await ad.getGroupMembershipForUser(userId.split('@')[0]);
		const groupPerms = [];
		if (!groups) {
			moduleLogger.warn('user: ' + userId + ' not found.');
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
		moduleLogger.error(err);
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
			moduleLogger.warn('User: ' + userId + ' not found.');
		} else {
			groups.forEach((group) => {
				groupPerms.push(group.cn);
			});
		}

		return groupPerms;
	} catch (err) {
		moduleLogger.error(err);
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
			moduleLogger.error(err);
		} else {
			moduleLogger.info('added user in a group');
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
			moduleLogger.error(err);
		} else {
			moduleLogger.info('removed user from a group');
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
	const requestLogger = getRequestLogger(req);
	const loggingContext = createLoggingContext(req);

	try {
		let permissions =
			req.session.user && req.session.user.perms ? req.session.user.perms : [];
		for (let p of permissionToCheckFor) {
			if (hasPerm(p, permissions)) return next();
		}
	} catch (err) {
		requestLogger.error(
			{ err, ...loggingContext },
			'Error reading request permissions.'
		);
		return res.status(403).send();
	}
	return res.status(403).send();
};

// SAML PORTION

const updateLoginTime = async (req, res) => {
	const requestLogger = getRequestLogger(req);
	const loggingContext = createLoggingContext(req);

	let userid;
	
	if (env.SSO_DISABLED) {
		userid = req.get('SSL_CLIENT_S_DN_CN');
	} else {
		userid = req.user.id;
	}

	let dbClient = await pool.connect();

	try {
		let loginTimeSQL = 'UPDATE users SET lastlogin=NOW() WHERE username=$1';
		await dbClient.query(loginTimeSQL, [userid]);
	} catch (err) {
		requestLogger.error({ err, ...loggingContext });
	} finally {
		dbClient.release();
	}
};

const setUserSession = async (req, res) => {
	const requestLogger = getRequestLogger(req);
	const loggingContext = createLoggingContext(req);

	try {
		if (IS_DECOUPLED) {
			const modifiedReq = {user: {}, ...req};
			modifiedReq.user.cn = req?.user?.cn || req.get('x-env-ssl_client_certificate');
			req.session.user = await fetchUserInfo(modifiedReq);
			req.session.user.session_id = req.sessionID;
		} else {
			req.session.user = await fetchUserInfo(req);
			req.session.user.session_id = req.sessionID;
		}
		requestLogger.info(loggingContext, 'session started');
		SSORedirect(req, res);
	} catch (err) {
		requestLogger.error({ err, ...loggingContext });
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
			const requestLogger = getRequestLogger(req);
			const loggingContext = createLoggingContext(req);

			const referer = req.get('Referer');
			if (referer) {
				try {
					const parsedReferer = new URL(referer);
					const refererOrigin = parsedReferer.origin.replace('www.', '');
					const approvedClients = process.env.APPROVED_API_CALLERS.split(' ');
					// store referer origin in session in order to redirect to correct domain after SAML auth
					if (
						approvedClients.includes(refererOrigin) &&
						refererOrigin !== approvedClients[0]
					) {
						req.session.AlternateSsoOrigin = refererOrigin;
					}
				} catch (err) {
					requestLogger.error({ err, ...loggingContext });
				}
			}
			passport.authenticate('saml', { failureRedirect: '/login/fail' })(
				req,
				res,
				next
			);
		},
		(req, res) => {
			SSORedirect(req, res);
		}
	);

	app.post(
		'/login/callback',
		passport.authenticate('saml', { failureRedirect: '/login/fail' }),
		(_req, res) => {
			res.redirect('/api/setUserSession');
		}
	);

	app.get('/login/fail', (_req, res) => {
		res.status(401).send('Login failed');
	});

	app.get('/logout', function (req, res) {
		const requestLogger = getRequestLogger(req);
		const loggingContext = createLoggingContext(req);

		if (req.user == null) {
			return res.redirect('/');
		}
		samlStrategy.logout(req, function (err, uri) {
			if (!err) {
				return res.redirect('/login');
			}
			if (err) {
				requestLogger.error({ err, ...loggingContext });
			}
		});
	});

	app.post('/logout/callback', function (req, res) {
		req.logout();
		res.redirect('/login');
	});

	app.get(
		'/api/setUserSession',
		(req, res, next) => {
			if (req.isAuthenticated()) {
				updateLoginTime(req, res);
				return next();
			} else return res.redirect('/login');
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
	getMaxAge,
};

const getDisplayName = (req, user, adUser, cn) => {
	const requestLogger = getRequestLogger(req);
	const loggingContext = createLoggingContext(req);

	let ret = '';
	try {
		if (req?.user?.displayName) {
			// grab user display name from the request, if present
			ret = req.user.displayName;
		} else if (user?.displayname) {
			// next, check user object in postgres
			ret = user.displayname;
		} else if (adUser?.displayName) {
			// next check user in AD
			ret = adUser.displayName;
		} else {
			// finally, try to parse cn
			let parts = cn.split('.');
			if (parts.length >= 2) {
				// cn is in LAST.FIRST.MI.EDIPI format
				// we want display name to be FIRST LAST
				ret = `${parts[1]} ${parts[0]}`;
			}
		}
	} catch (err) {
		requestLogger.error({ err, ...loggingContext });
	} finally {
		return ret;
	}
};
