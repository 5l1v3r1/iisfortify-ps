## IISFortify-PS ##
#### by Chris Campbell ####

Compatiable with Server 2012 R2 and Server 2016. Untested on Server 2008 R2 and earlier.  

Requires IIS URL Rewrite module if applying security response headers: https://www.iis.net/downloads/microsoft/url-rewrite  

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

- Restricts available TLS protocols and cipher suites for both client and server.  
- Policy defined via SchUseStrongCrypto and DefaultSecureProtocols directives. References:  
  - https://support.microsoft.com/en-nz/help/3155464/ms16-065-description-of-the-tls-ssl-protocol-information-disclosure-vu  
  - https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-a-default-secure-protocols-in  