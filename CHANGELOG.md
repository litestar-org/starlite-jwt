# Changelog

[1.0.0]

- initial release

[1.1.0]

- update `jwt-auth` to have `openapi_components` and `security_requirements` properties that can be used for OpenAPI 3.1 docs generation.
- Use `cryptography` as `python-jose` backend
- Adjustments to `Token` model.

[1.1.1]

- update dependencies and adjust `authenticate_request` to Starlite `1.6.0+`

[1.2.0]

- update implementation for Starlite `1.16.0+` compatibility.

[1.3.0]

- update implementation for Starlite `1.20.0+` compatibility.
- implements `OAuth2PasswordBearerAuth` as a pre-configured JWT backend.
- implements `JWTCookieAuth` as an additional JWT backend.
