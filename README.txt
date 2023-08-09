Requirement
- python 3.10
- Flask 2.3.2
- package pyOpenSSL installed

How to run
- Open file gen_saml_response.py and set SSO_REDIRECT_URL = <core_sso_redirect_url>
- Run file run.bat to start IDP server

This IDP will returns these claims:
 - first_name: mail
 - last_name: test


