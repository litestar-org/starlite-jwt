from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal, Optional, Union

import httpx
from pydantic import BaseConfig
from pydantic_openapi_schema.v3_1_0 import Components, SecurityScheme
from starlette.status import HTTP_201_CREATED
from starlite import DefineMiddleware, Response
from starlite.enums import MediaType

from starlite_jwt.jwt_auth import JWTAuth
from starlite_jwt.middleware import JWTCookieAuthenticationMiddleware

if TYPE_CHECKING:
    from datetime import timedelta


@lru_cache(maxsize=1)
def fetch_gcp_iap_certs() -> dict[str, str]:
    """Fetches the Google IAP JWT Public Keys"""
    response = httpx.get("https://www.gstatic.com/iap/verify/public_key")
    return response.json()  # type: ignore


@lru_cache(maxsize=2)
def fetch_gcp_metadata(item_name: str) -> str:
    """Fetches the Google IAP JWT Public Keys"""
    response = httpx.get(
        f"http://metadata.google.internal/computeMetadata/v1/project/{item_name}", headers={"Metadata-Flavor": "Google"}
    )
    return response.text


class IAPAuth(JWTAuth):
    """Google Cloud Identity-Aware Proxy Authentication.

    This class is an alternate entry point to the library, and it
    includes all of the functionality of the `JWTAuth` class and adds
    support authentication using Google's IAP proxy.
    """

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    name: str = "GoogleIAPAuth"
    """
    `ES256` is currently the only supported algorithm for JWT
    """
    algorithm: Literal["ES256"] = "ES256"
    """
    `ES256` is currently the only supported algorithm for JWT
    """
    auth_header: Literal["X-Goog-IAP-JWT-Assertion"] = "X-Goog-IAP-JWT-Assertion"
    """
    Request header key from which to retrieve the token. Google IAP expect the header to be `X-Goog-IAP-JWT-Assertion`
    """

    @property
    def openapi_components(self) -> Components:
        """Creates OpenAPI documentation for the JWT Cookie auth scheme.

        Returns:
            An [Components][pydantic_schema_pydantic.v3_1_0.components.Components] instance.
        """
        return Components(
            securitySchemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="http",
                    scheme="Bearer",
                    name=self.name,
                    security_scheme_in="header",
                    bearerFormat="JWT",
                    description="Google Identity-Aware Proxy Authentication",
                )
            }
        )

    @property
    def middleware(self) -> DefineMiddleware:
        """Creates `JWTCookieAuthenticationMiddleware` wrapped in Starlite's
        `DefineMiddleware`.

        Returns:
            An instance of [DefineMiddleware][starlite.middleware.base.DefineMiddleware].
        """
        return DefineMiddleware(
            JWTCookieAuthenticationMiddleware,
            algorithm=self.algorithm,
            auth_header=self.auth_header,
            retrieve_user_handler=self.retrieve_user_handler,
            token_secret=self.token_secret,
            exclude=self.exclude,
        )

    def login(
        self,
        identifier: str,
        *,
        response_body: Optional[Any] = None,
        response_media_type: Union[str, MediaType] = MediaType.JSON,
        response_status_code: int = HTTP_201_CREATED,
        token_expiration: Optional["timedelta"] = None,
        token_issuer: Optional[str] = None,
        token_audience: Optional[str] = None,
        token_unique_jwt_id: Optional[str] = None,
    ) -> Response[Any]:
        """Create a response with a JWT header. Calls the
        'JWTAuth.store_token_handler' to persist the token 'sub'.

        Args:
            identifier: Encoded JWT token from header.
            response_body: An optional response body to send.
            response_media_type: An optional 'Content-Type'. Defaults to 'application/json'.
            response_status_code: An optional status code for the response. Defaults to '201 Created'.
            token_expiration: No effect in IAP Auth.
            token_issuer: No effect in IAP Auth.
            token_audience: No effect in IAP Auth.
            token_unique_jwt_id: No effect in IAP Auth.

        Returns:
            A [Response][starlite.response.Response] instance.
        """

        return Response(
            content=response_body,
            headers={self.auth_header: identifier},
            media_type=response_media_type,
            status_code=response_status_code,
        )
