module.exports = {
	SAML_OBJECT: {
		acceptedClockSkewMs: '5000',
		attributeConsumingServiceIndex: '1',
		authnRequestBinding: 'HTTP-POST',
		issuer: process.env.SAML_ISSUER,
		callbackUrl: process.env.SAML_CALLBACK_URL,
		entryPoint: process.env.SAML_ENTRYPOINT,
		cert: process.env.SAML_CERT,
		skipRequestCompression: true,
		signatureAlgorithm: 'sha512',
		identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
	},
	SAML_CLAIM_ID: 'urn:oid:1.2.840.113556.1.4.656',
	SAML_CLAIM_EMAIL: 'urn:oid:0.9.2342.19200300.100.1.3',
	SAML_CLAIM_DISPLAYNAME: 'urn:oid:2.16.840.1.113730.3.1.241',
	SAML_CLAIM_PERMS: 'urn:oid:2.5.6.8',
}