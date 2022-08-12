[![Quality Gate Status](https://sonarqube.vdms.advana.boozallencsn.com/api/project_badges/measure?project=advana-modules-advana-module-api-auth&metric=alert_status&token=squ_671ae7d6e3b302b12a2a07c79ef7a3a1c1765db9)](https://sonarqube.vdms.advana.boozallencsn.com/dashboard?id=advana-modules-advana-module-api-auth)

# Advana API Authentication

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
'["nnnn", "keyboard cat"]'
```