const SamlStrategy = require('@node-saml/passport-saml').Strategy;
const SAML_CONFIGS = require('./samlConfigs');

module.exports = new SamlStrategy(SAML_CONFIGS.SAML_OBJECT, function (
	profile,
	done
) {
	const perms = new Set();
	profile
		.getAssertion()
		.Assertion.AttributeStatement.forEach((attributeStatement) => {
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
});
