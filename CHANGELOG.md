# Changelog

[1.0.0]

- initial release

[1.1.0]

- add `cryptography` as `python-jose` backend
- update `jwt-auth` to have `openapi_components` and `security_requirements` properties that can be used for OpenAPI 3.1 docs generation.
- update to `Token` model.

[1.1.1]

- update dependencies and adjust `authenticate_request` to Starlite `1.6.0+`

[1.2.0]

- update implementation for Starlite `1.16.0+` compatibility.

[1.3.0]

- add `JWTCookieAuth` as an additional JWT backend.
- add `OAuth2PasswordBearerAuth` as a pre-configured JWT backend.
- update implementation for Starlite `1.20.0+` compatibility.

[1.4.0]

- add Python `3.11` support.
- require Starlite `>=1.24.0`.
- update `RetrieveUserHandler` to support accepting the `connection` as an arg.

[1.4.1]

- updated authentication header and cookie to include the security scheme prefixed to the JWT token
