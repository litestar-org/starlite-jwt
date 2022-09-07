# Starlite JWT

<!-- markdownlint-disable -->
<img alt="Starlite logo" src="./starlite-banner.svg" width="100%" height="auto">
<!-- markdownlint-restore -->

<div align="center">

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=starlite-api_jwt-auth&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=starlite-api_jwt-auth)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=starlite-api_jwt-auth&metric=coverage)](https://sonarcloud.io/summary/new_code?id=starlite-api_jwt-auth)

[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=starlite-api_jwt-auth&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=starlite-api_jwt-auth)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=starlite-api_jwt-auth&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=starlite-api_jwt-auth)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=starlite-api_jwt-auth&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=starlite-api_jwt-auth)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=starlite-api_jwt-auth&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=starlite-api_jwt-auth)

[![Discord](https://img.shields.io/discord/919193495116337154?color=blue&label=chat%20on%20discord&logo=discord)](https://discord.gg/X3FJqy8d2j)
[![Matrix](https://img.shields.io/badge/%5Bm%5D%20chat%20on%20Matrix-bridged-blue)](https://matrix.to/#/#starlitespace:matrix.org)

</div>

This library offers simple JWT authentication for [Starlite](https://github.com/starlite-api/starlite).

Checkout [the docs 📚](https://starlite-api.github.io/starlite-jwt/).

## Installation

```shell
pip install starlite-jwt
```

This library uses the excellent [python-jose](https://github.com/mpdavis/python-jose) library, which supports multiple
cryptographic backends. You can install either [pyca/cryptography](http://cryptography.io/)
or [pycryptodome](https://pycryptodome.readthedocs.io/en/latest/), and it will be used as the backend automatically. Note
that if you want to use a certificate based encryption scheme, you must install one of these backends - please refer to
the [python-jose](https://github.com/mpdavis/python-jose) readme for more details.

## Example

```python
import os
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, EmailStr
from starlite import OpenAPIConfig, Request, Response, Starlite, get

from starlite_jwt import JWTAuth, Token


# Let's assume we have a User model that is a pydantic model.
# This though is not required - we need some sort of user class -
# but it can be any arbitrary value, e.g. an SQLAlchemy model, a representation of a MongoDB  etc.
class User(BaseModel):
    id: UUID
    name: str
    email: EmailStr


# The JWTAuth package requires a handler callable that takes a unique identifier, and returns the 'User'
# instance correlating to it.
#
# The identifier is the 'sub' key of the JWT, and it usually correlates to a user ID.
# It can be though any arbitrary value you decide upon - as long as the handler function provided
# can receive this value and return the model instance for it.
#
# Note: The callable can be either sync or async - both will work.
async def retrieve_user_handler(unique_identifier: str) -> Optional[User]:
    # logic here to retrieve the user instance
    ...


# The minimal configuration required for the library is the callable for the 'retrieve_user_handler' key, and a string
# value for the token secret.
#
# Important: secrets should never be hardcoded. Its best practice to pass the secret using ENV.
#
# Tip: It's also a good idea to use the pydantic settings management functionality
jwt_auth = JWTAuth(
    retrieve_user_handler=retrieve_user_handler,
    token_secret=os.environ.get("JWT_SECRET", "abcd123"),
    # we are specifying which endpoints should be excluded from authentication. In this case the login endpoint
    # and our openAPI docs.
    exclude=["/login", "/schema"],
)


# Given an instance of 'JWTAuth' we can create a login handler function:
@get("/login")
def login_handler() -> Response[User]:
    # we have a user instance - probably by retrieving it from persistence using another lib.
    # what's important for our purposes is to have an identifier:
    user = User(name="Moishe Zuchmir", email="zuchmir@moishe.com", id=uuid4())

    response = jwt_auth.login(identifier=str(user.id), response_body=user)

    # you can do whatever you want to update the response instance here
    # e.g. response.set_cookie(...)

    return response


# We also have some other routes, for example:
@get("/some-path")
def some_route_handler(request: Request[User, Token]) -> Any:
    # request.user is set to the instance of user returned by the middleware
    assert isinstance(request.user, User)
    # request.auth is the instance of 'starlite_jwt.Token' created from the data encoded in the auth header
    assert isinstance(request.auth, Token)
    # do stuff ...


# We add the jwt security schema to the OpenAPI config.
openapi_config = OpenAPIConfig(
    title="My API",
    version="1.0.0",
    components=[jwt_auth.openapi_components],
    security=[jwt_auth.security_requirement],
)

# We initialize the app instance, passing to it the 'jwt_auth.middleware' and the 'openapi_config'.
app = Starlite(
    route_handlers=[login_handler, some_route_handler],
    middleware=[jwt_auth.middleware],
    openapi_config=openapi_config,
)
```

## Contributing

Starlite and all its official libraries is open to contributions big and small.

You can always [join our discord](https://discord.gg/X3FJqy8d2j) server
or [join our Matrix](https://matrix.to/#/#starlitespace:matrix.org) space to discuss contributions and project
maintenance. For guidelines on how to contribute to this library, please see [the contribution guide](CONTRIBUTING.md).
