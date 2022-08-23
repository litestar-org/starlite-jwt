import string
from datetime import timedelta
from typing import TYPE_CHECKING, Dict, Optional

import pytest
from hypothesis import given
from hypothesis.strategies import integers, none, one_of, sampled_from, text, timedeltas
from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED
from starlite import Request, Response, get
from starlite.testing import create_test_client

from starlite_jwt_auth import JWTAuth, Token
from tests.conftest import User, UserFactory

if TYPE_CHECKING:

    from starlite.cache import SimpleCacheBackend

algorithms = [
    "HS256",
    "HS384",
    "HS512",
]

headers = ["Authorization", "X-API-Key"]


@pytest.mark.asyncio()
@given(
    algorithm=sampled_from(algorithms),
    auth_header=sampled_from(headers),
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
    default_token_expiration: timedelta,
    token_secret: str,
    response_status_code: int,
    token_expiration: Optional[timedelta],
    token_issuer: Optional[str],
    token_audience: Optional[str],
    token_unique_jwt_id: Optional[str],
) -> None:
    user = UserFactory.build()

    await mock_db.set(str(user.id), user, 120)

    async def retrieve_user_handler(sub: str) -> "User":
        stored_user = await mock_db.get(sub)
        assert stored_user
        return stored_user

    jwt_auth = JWTAuth(
        algorithm=algorithm,
        auth_header=auth_header,
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
        response = jwt_auth.login(
            identifier=str(user.id),
            response_body=user,
            response_status_code=response_status_code,
            token_expiration=token_expiration,
            token_issuer=token_issuer,
            token_audience=token_audience,
            token_unique_jwt_id=token_unique_jwt_id,
        )
        return response

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


async def test_path_exclusion() -> None:
    async def retrieve_user_handler(_: str) -> None:
        return None

    jwt_auth = JWTAuth(token_secret="abc123", retrieve_user_handler=retrieve_user_handler, exclude=["north", "south"])

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


def test_security_schema() -> None:
    jwt_auth = JWTAuth(token_secret="abc123", retrieve_user_handler=lambda _: None)
    assert jwt_auth.security_schema.dict() == {
        "bearerFormat": "JWT",
        "description": "JWT api-key authentication and authorization.",
        "flows": None,
        "name": "Authorization",
        "openIdConnectUrl": None,
        "scheme": "Bearer",
        "security_scheme_in": None,
        "type": "http",
    }
