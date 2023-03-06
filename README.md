## Env Variables
* REDIS_URL

* PG_USER
* PG_PASSWORD
* PG_HOST
* PG_UM_DB

* TLS_KEY_FILEPATH
* TLS_KEY_PASSPHRASE
* APPROVED_API_CALLERS
* COOKIE_DOMAIN
* SECURE_SESSION
* DISABLE_SSO
* EXPRESS_SESSION_SECRET JSON array of strings used as secrets like
```
'["new secret first", "older secrets later"]'
```
* EXPRESS_SESSION_MAX_AGE session cookie max age in seconds
* SAML_ISSUER
* SAML_CALLBACK_URL
* SAML_ENTRYPOINT
* SAML_LOGOUT_URL
* SAML_LOGOUT_CALLBACK_URL
* SAML_CERT

* AD_ENABLED (true/false) This one turns on and off pulling permissions from AD.
* LDAP_URL (ldaps://ldap.example.com)
* LDAP_USERNAME (dev.team.da@DRCED)
* LDAP_PASSWORD (password)
* LDAP_CERT (Cert for LDAP)
* LDAP_USER_FOLDER_CN (DC=drced,DC=local)
