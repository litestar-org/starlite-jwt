from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Union

from pydantic import BaseConfig, BaseModel
from pydantic_openapi_schema.v3_1_0 import (
    Components,
    SecurityRequirement,
    SecurityScheme,
)
from starlette.status import HTTP_201_CREATED
from starlite import DefineMiddleware, Response
from starlite.enums import MediaType

from starlite_jwt.middleware import JWTAuthenticationMiddleware
from starlite_jwt.token import Token
from starlite_jwt.types import RetrieveUserHandler


class JWTAuth(BaseModel):
    """JWT Authentication Configuration.

    This class is the main entry point to the library, and it includes
    methods to create the middleware, provide login functionality, and
    create OpenAPI documentation.
    """

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    algorithm: str = "HS256"
    """
    Algorithm to use for JWT hashing.
    """
    auth_header: str = "Authorization"
    """
    Request header key from which to retrieve the token. E.g. 'Authorization' or 'X-Api-Key'.
    """
    default_token_expiration: timedelta = timedelta(days=1)
    """
    The default value for token expiration.
    """
    retrieve_user_handler: RetrieveUserHandler
    """
    Callable that receives the 'sub' value of a token, which represents the 'subject' of the token (usually a user ID
    or equivalent value) and returns a 'user' value.

    Notes:
    - User can be any arbitrary value,
    - The callable can be sync or async.
    """
    token_secret: str
    """
    Key with which to generate the token hash.

    Notes:
    - This value should be kept as a secret and the standard practice is to inject it into the environment.
    """
    exclude: Optional[Union[str, List[str]]] = None
    """
    A pattern or list of patterns to skip in the authentication middleware.
    """
    openapi_security_scheme_name: str = "BearerToken"
    """
    The value to use for the OpenAPI security scheme and security requirements
    """

    @property
    def openapi_components(self) -> Components:
        """Creates OpenAPI documentation for the JWT auth schema used.

        Returns:
            An [Components][pydantic_schema_pydantic.v3_1_0.components.Components] instance.
        """
        return Components(
            securitySchemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="http",
                    scheme="Bearer",
                    name=self.auth_header,
                    bearerFormat="JWT",
                    description="JWT api-key authentication and authorization.",
                )
            }
        )

    @property
    def security_requirement(self) -> SecurityRequirement:
        """
        Returns:
            An OpenAPI 3.1 [SecurityRequirement][pydantic_schema_pydantic.v3_1_0.security_requirement.SecurityRequirement] dictionary.
        """
        return {self.openapi_security_scheme_name: []}

    @property
    def middleware(self) -> DefineMiddleware:
        """Creates `JWTAuthenticationMiddleware` wrapped in Starlite's
        `DefineMiddleware`.

        Returns:
            An instance of [DefineMiddleware][starlite.middleware.base.DefineMiddleware].
        """
        return DefineMiddleware(
            JWTAuthenticationMiddleware,
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
        token_expiration: Optional[timedelta] = None,
        token_issuer: Optional[str] = None,
        token_audience: Optional[str] = None,
        token_unique_jwt_id: Optional[str] = None,
    ) -> Response[Any]:
        """Create a response with a JWT header. Calls the
        'JWTAuth.store_token_handler' to persist the token 'sub'.

        Args:
            identifier: Unique identifier of the token subject. Usually this is a user ID or equivalent kind of value.
            response_body: An optional response body to send.
            response_media_type: An optional 'Content-Type'. Defaults to 'application/json'.
            response_status_code: An optional status code for the response. Defaults to '201 Created'.
            token_expiration: An optional timedelta for the token expiration.
            token_issuer: An optional value of the token 'iss' field.
            token_audience: An optional value for the token 'aud' field.
            token_unique_jwt_id: An optional value for the token 'jti' field.

        Returns:
            A [Response][starlite.response.Response] instance.
        """
        encoded_token = self.create_token(
            identifier=identifier,
            token_expiration=token_expiration,
            token_issuer=token_issuer,
            token_audience=token_audience,
            token_unique_jwt_id=token_unique_jwt_id,
        )
        return Response(
            content=response_body,
            headers={self.auth_header: encoded_token},
            media_type=response_media_type,
            status_code=response_status_code,
        )

    def create_token(
        self,
        identifier: str,
        token_expiration: Optional[timedelta] = None,
        token_issuer: Optional[str] = None,
        token_audience: Optional[str] = None,
        token_unique_jwt_id: Optional[str] = None,
    ) -> str:
        """Creates a Token instance from the passed in parameters, persists and
        returns it.

        Args:
            identifier: Unique identifier of the token subject. Usually this is a user ID or equivalent kind of value.
            token_expiration: An optional timedelta for the token expiration.
            token_issuer: An optional value of the token 'iss' field.
            token_audience: An optional value for the token 'aud' field.
            token_unique_jwt_id: An optional value for the token 'jti' field.

        Returns:
            The created token.
        """
        token = Token(
            sub=identifier,
            exp=(datetime.now(timezone.utc) + (token_expiration or self.default_token_expiration)),
            iss=token_issuer,
            aud=token_audience,
            jti=token_unique_jwt_id,
        )
        encoded_token = token.encode(secret=self.token_secret, algorithm=self.algorithm)

        return encoded_token
