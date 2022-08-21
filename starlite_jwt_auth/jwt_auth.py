from datetime import timedelta
from typing import Any, Optional, Tuple, Union
from uuid import UUID

from anyio.to_thread import run_sync
from pydantic import BaseConfig, BaseModel
from pydantic_openapi_schema.v3_1_0 import SecurityScheme
from starlette.requests import HTTPConnection
from starlette.status import HTTP_201_CREATED
from starlette.types import ASGIApp
from starlite import BaseRouteHandler, MediaType, NotAuthorizedException, Response
from starlite.types import Guard
from starlite.utils import is_async_callable

from starlite_jwt_auth.middleware import JWTAuthenticationMiddleware
from starlite_jwt_auth.token import Token
from starlite_jwt_auth.types import RetrieveUserHandler, StoreTokenHandler


class JWTAuth(BaseModel):
    """JWT Authentication Configuration.

    This class is the main entry point to the library and it includes
    methods to create the middleware, provide login functionality, and
    create OpenAPI documentation.
    """

    class Config(BaseConfig):
        arbitrary_types_allowed = True

    algorithm: str = "HS256"
    """
    Algorithm to use for JWT hashing.
    """
    auth_header_key: str = "Authorization"
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
    store_token_handler: StoreTokenHandler
    """
    Callable that receives a 'token' instance and persists its sub value.

    Notes:
    - Its not important to persist the token as is. What is important is that we would be able to use the 'sub' value of
        the token to retrieve the desired 'user' datum with the 'retrieve_user_handler' function.
    """

    token_secret: str
    """
    Key with which to generate the token hash.

    Notes:
    - This value should be kept as a secret and the standard practice is to inject it into the environment.

    """

    def create_security_schema(self) -> SecurityScheme:
        """Creates OpenAPI documentation for the JWT auth schema used.

        Returns:
            An pydantic model instance representing an OpenAPI 3.1 SecuritySchema.
        """
        return SecurityScheme(
            type="http",
            scheme="Bearer",
            name=self.auth_header_key,
            bearerFormat="JWT",
            description="JWT api-key authentication and authorization.",
        )

    def create_middleware(self, app: "ASGIApp") -> "ASGIApp":
        """Creates a 'JWTAuthenticationMiddleware' based on config values.

        Notes:
            - this function should be passed as is to Starlite or one of its layers 'middleware' kwargs.

        Args:
            app: An ASGIApp, this value is the next ASGI handler to call in the middleware stack.

        Returns:
            An ASGIApp.
        """
        return JWTAuthenticationMiddleware(
            app=app,
            auth=self,
        )

    def create_guard(self) -> Guard:
        async def guard(connection: HTTPConnection, handler: BaseRouteHandler) -> None:
            """Guard function that allows Starlite route handler functions to
            skip authorization by setting the 'opt' key 'skip_jwt_auth' to
            True.

            Examples:
                ```python
                from starlite import get


                @get("/", opt={"skip_jwt_auth": True})
                def my_handler() -> None:
                    ...
                ```

            Args:
                connection: An Starlette HTTPConnection instance.
                handler: A Starlite route handler class instance.

            Raises:
                [NotAuthorizedException][starlite.exceptions.NotAuthorizedException]: If token is
                    invalid or user is not found.

            Returns:
                None
            """
            if handler.opt.get("skip_jwt_auth", False):
                return
            await self.authenticate(connection=connection)

        return guard

    async def login(
        self,
        identifier: Union[str, UUID],
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
        encoded_token = self._create_token(
            identifier=identifier,
            token_expiration=token_expiration,
            token_issuer=token_issuer,
            token_audience=token_audience,
            token_unique_jwt_id=token_unique_jwt_id,
        )
        return Response(
            content=response_body,
            headers={self.auth_header_key: encoded_token},
            media_type=response_media_type,
            status_code=response_status_code,
        )

    async def authenticate(self, connection: HTTPConnection) -> Tuple[Any, Token]:
        """
        Authenticates a connection based on the JWT in the header.
        Args:
            connection: An Starlette HTTPConnection instance.

        Returns:
            A tuple of the 'user' data and the token instance.
        """
        auth_header = connection.headers.get(self.auth_header_key)
        if not auth_header:
            raise NotAuthorizedException("JWT not found in request header")

        token = Token.decode(
            encoded_token=auth_header,
            secret=self.token_secret,
            algorithm=self.algorithm,
        )
        if is_async_callable(self.store_token_handler):
            user = await self.retrieve_user_handler(token.sub)
        else:
            user = await run_sync(self.retrieve_user_handler, token.sub)

        if not user:
            raise NotAuthorizedException()

        return user, token

    async def _create_token(
        self,
        identifier: Union[str, UUID],
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
            exp=token_expiration or self.default_token_expiration,
            iss=token_issuer,
            aud=token_audience,
            jti=token_unique_jwt_id,
        )
        encoded_token = token.encode(secret=self.token_secret, algorithm=self.algorithm)

        if is_async_callable(self.store_token_handler):
            await self.store_token_handler(token)
        else:
            await run_sync(self.store_token_handler, token)

        return encoded_token
