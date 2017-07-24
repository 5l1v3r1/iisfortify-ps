## IISFortify-PS ##
#### by Chris Campbell ####

Based on: https://www.hass.de/content/setup-your-iis-ssl-perfect-forward-secrecy-and-tls-12

Compatiable with Server 2008 R2, Server 2012 R2, Server 2016.

Requires IIS URL Rewrite module: https://www.iis.net/downloads/microsoft/url-rewrite

### HTTP Reponse Headers ###

- Removed:
 - Server
 - X-Powered-By
- Added:
 - Strict-Transport-Security: max-age=31536000; includeSubDomains
 - cache_control: private, max-age=0, no-cache
 - X-Content-Type-Options: nosniff
 - X-XSS-Protection: mode=block
 - X-Frame-Options: SAMEORIGIN
 - X-Download-Options: noopen

### TLS Configuration ###

- Backed up to a registry script prior to update.
- MPUH, PCT, SSLv2 and SSLv3 disabled.
- TLSv1.0 disabled on Server 2012 R2+.
- TLSv1.1 and TLSv1.2 enabled.
- NULL, DES and RCx ciphers disabled.
- TDES and AES ciphers enabled.
- MD5 hash disabled.
- SHA hashes enabled.
- DH, ECDH and PKCS key exchanges enabled.
- Cipher lists optimised for given OS.