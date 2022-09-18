import string
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Dict, Optional
from uuid import uuid4

import pytest
from hypothesis import given
from hypothesis.strategies import integers, none, one_of, sampled_from, text, timedeltas
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from starlite import OpenAPIConfig, Request, Response, Starlite, get
from starlite.testing import create_test_client

from starlite_jwt import JWTAuth, OAuth2PasswordBearerAuth, Token
from tests.conftest import User, UserFactory

if TYPE_CHECKING:

    from starlite.cache import SimpleCacheBackend


@pytest.mark.asyncio()
@given(
    algorithm=sampled_from(
        [
            "HS256",
            "HS384",
            "HS512",
        ]
    ),
    auth_header=sampled_from(["Authorization", "X-API-Key"]),
    auth_cookie=sampled_from(["token", "accessToken"]),
    default_token_expiration=timedeltas(min_value=timedelta(seconds=30), max_value=timedelta(weeks=1)),
    token_secret=text(min_size=10),
    response_status_code=integers(min_value=200, max_value=201),
    token_expiration=timedeltas(min_value=timedelta(seconds=30), max_value=timedelta(weeks=1)),
    token_issuer=one_of(none(), text(max_size=256)),
    token_audience=one_of(none(), text(max_size=256, alphabet=string.ascii_letters)),
    token_unique_jwt_id=one_of(none(), text(max_size=256)),
)
async def test_jwt_auth(
    mock_db: "SimpleCacheBackend",
    algorithm: str,
    auth_header: str,
    auth_cookie: str,
    default_token_expiration: timedelta,
    token_secret: str,
    response_status_code: int,
    token_expiration: timedelta,
    token_issuer: Optional[str],
    token_audience: Optional[str],
    token_unique_jwt_id: Optional[str],
) -> None:
    user = UserFactory.build()

    await mock_db.set(str(user.id), user, 120)

    async def retrieve_user_handler(sub: str) -> Optional["User"]:
        stored_user = await mock_db.get(sub)
        return stored_user

    jwt_auth = JWTAuth(
        algorithm=algorithm,
        auth_header=auth_header,
        auth_cookie=auth_cookie,
        default_token_expiration=default_token_expiration,
        token_secret=token_secret,
        retrieve_user_handler=retrieve_user_handler,
    )

    @get("/my-endpoint", middleware=[jwt_auth.middleware])
    def my_handler(request: Request["User", Token]) -> None:
        assert request.user
        assert request.user.dict() == user.dict()
        assert request.auth.sub == str(user.id)

    @get("/login")
    def login_handler() -> Response["User"]:
        return jwt_auth.login(
            identifier=str(user.id),
            response_body=user,
            response_status_code=response_status_code,
            token_expiration=token_expiration,
            token_issuer=token_issuer,
            token_audience=token_audience,
            token_unique_jwt_id=token_unique_jwt_id,
        )

    with create_test_client(route_handlers=[my_handler, login_handler]) as client:
        response = client.get("/login")
        assert response.status_code == response_status_code
        encoded_token = response.headers.get(auth_header)
        assert encoded_token
        decoded_token = Token.decode(encoded_token=encoded_token, secret=token_secret, algorithm=algorithm)
        assert decoded_token.sub == str(user.id)
        assert decoded_token.iss == token_issuer
        assert decoded_token.aud == token_audience
        assert decoded_token.jti == token_unique_jwt_id

        response = client.get("/my-endpoint")
        assert response.status_code == HTTP_401_UNAUTHORIZED

        response = client.get("/my-endpoint", headers={auth_header: encoded_token})
        assert response.status_code == HTTP_200_OK

        response = client.get("/my-endpoint", cookies={auth_cookie: encoded_token})
        assert response.status_code == HTTP_200_OK

        response = client.get("/my-endpoint", headers={auth_header: uuid4().hex})
        assert response.status_code == HTTP_401_UNAUTHORIZED

        response = client.get("/my-endpoint", cookies={auth_cookie: uuid4().hex})
        assert response.status_code == HTTP_401_UNAUTHORIZED

        fake_token = Token(
            sub=uuid4().hex,
            iss=token_issuer,
            aud=token_audience,
            jti=token_unique_jwt_id,
            exp=(datetime.now(timezone.utc) + token_expiration),
        ).encode(secret=token_secret, algorithm=algorithm)

        response = client.get("/my-endpoint", headers={auth_header: fake_token})
        assert response.status_code == HTTP_401_UNAUTHORIZED

        response = client.get("/my-endpoint", cookies={auth_cookie: fake_token})
        assert response.status_code == HTTP_401_UNAUTHORIZED


async def test_path_exclusion() -> None:
    async def retrieve_user_handler(_: str) -> None:
        return None

    jwt_auth = JWTAuth(
        token_secret="abc123",
        retrieve_user_handler=retrieve_user_handler,
        exclude=["north", "south"],
    )

    @get("/north/{value:int}")
    def north_handler(value: int) -> Dict[str, int]:
        return {"value": value}

    @get("/south")
    def south_handler() -> None:
        return None

    @get("/west")
    def west_handler() -> None:
        return None

    with create_test_client(
        route_handlers=[north_handler, south_handler, west_handler], middleware=[jwt_auth.middleware]
    ) as client:
        response = client.get("/north/1")
        assert response.status_code == HTTP_200_OK

        response = client.get("/south")
        assert response.status_code == HTTP_200_OK

        response = client.get("/west")
        assert response.status_code == HTTP_401_UNAUTHORIZED


def test_openapi() -> None:
    jwt_auth = JWTAuth(token_secret="abc123", retrieve_user_handler=lambda _: None)
    assert jwt_auth.openapi_components.dict(exclude_none=True) == {
        "securitySchemes": {
            "BearerToken": {
                "type": "http",
                "description": "JWT api-key authentication and authorization.",
                "name": "Authorization",
                "scheme": "Bearer",
                "bearerFormat": "JWT",
            }
        }
    }
    assert jwt_auth.security_requirement == {"BearerToken": []}

    openapi_config = OpenAPIConfig(
        title="my api",
        version="1.0.0",
        components=[jwt_auth.openapi_components],
        security=[jwt_auth.security_requirement],
    )
    app = Starlite(route_handlers=[], openapi_config=openapi_config)
    assert app.openapi_schema.dict(exclude_none=True) == {  # type: ignore
        "openapi": "3.1.0",
        "info": {"title": "my api", "version": "1.0.0"},
        "servers": [{"url": "/"}],
        "paths": {},
        "components": {
            "securitySchemes": {
                "BearerToken": {
                    "type": "http",
                    "description": "JWT api-key authentication and authorization.",
                    "name": "Authorization",
                    "scheme": "Bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
        "security": [{"BearerToken": []}],
    }


def test_oauth2_password_bearer() -> None:
    jwt_auth = OAuth2PasswordBearerAuth(  # nosec
        token_url="/login", token_secret="abc123", retrieve_user_handler=lambda _: None
    )
    assert jwt_auth.openapi_components.dict(exclude_none=True) == {
        "securitySchemes": {
            "BearerToken": {
                "type": "oauth2",
                "description": "OAUTH2 password bearer authentication and authorization.",
                "name": "Authorization",
                "scheme": "Bearer",
                "bearerFormat": "JWT",
                "flows": {"password": {"tokenUrl": "/login", "scopes": {}}},
            }
        }
    }
    assert jwt_auth.security_requirement == {"BearerToken": []}

    openapi_config = OpenAPIConfig(
        title="my api",
        version="1.0.0",
        components=[jwt_auth.openapi_components],
        security=[jwt_auth.security_requirement],
    )
    app = Starlite(route_handlers=[], openapi_config=openapi_config)
    assert app.openapi_schema.dict(exclude_none=True) == {  # type: ignore
        "openapi": "3.1.0",
        "info": {"title": "my api", "version": "1.0.0"},
        "servers": [{"url": "/"}],
        "paths": {},
        "components": {
            "securitySchemes": {
                "BearerToken": {
                    "type": "oauth2",
                    "description": "OAUTH2 password bearer authentication and authorization.",
                    "name": "Authorization",
                    "scheme": "Bearer",
                    "bearerFormat": "JWT",
                    "flows": {"password": {"tokenUrl": "/login", "scopes": {}}},
                }
            }
        },
        "security": [{"BearerToken": []}],
    }
