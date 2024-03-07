const { createChildLogger, hashValue, logger } = require('@advana/logger');
const { API_AUTH_LOG_LEVEL, SSO_DISABLED } = require('./environment');

const loggerOptions = {
	source: 'api-auth',
	level: API_AUTH_LOG_LEVEL ?? logger.level,
};

/**
 * A child instance of the default logger for logging module events.
 * @internal
 * @since 2.6.0
 */
const moduleLogger = createChildLogger(logger, loggerOptions);

/**
 * Gets a child instance of the request logger for logging module events.
 * @internal
 * @since 2.6.0
 */
const getRequestLogger = (req) => {
	if (!req.log) {
		return moduleLogger;
	}
	return createChildLogger(req.log, loggerOptions);
};

/**
 * Creates an `auth` logging context with basic information, and adds the req
 * logging context if not provided by httpLogger.
 * @returns The logging context
 * @internal
 * @since 2.6.0
 */
const createLoggingContext = (req) => {
	const context = {
		auth: {
			authenticated: SSO_DISABLED
				? SSO_DISABLED
				: req.isAuthenticated && req.isAuthenticated(),
		},
	};

	if (SSO_DISABLED) context.auth.sso = 'disabled';

	// if req.log exists, it means we're using httpLogger, which should already
	// log all of this data. use the same structure for consistency, but don't
	// create a duplicate req object.
	if (!req.log) {
		const sessionID = hashValue(req.sessionID);
		context.req = {
			id: req.id,
			remoteAddress: req.remoteAddress,
			sessionID,
			session: {
				id: sessionID,
				user: {
					id: req.session?.user?.id,
					disabled: req.session?.user?.disabled,
				},
			},
		};
	}

	return context;
};

module.exports = {
	createLoggingContext,
	getRequestLogger,
	moduleLogger,
};
