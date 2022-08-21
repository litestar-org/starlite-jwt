from typing import Any, Awaitable, Callable, Union
from uuid import UUID

from starlite_jwt_auth import Token

RetrieveUserHandler = Union[Callable[[Union[str, UUID]], Any], Callable[[Union[str, UUID]], Awaitable[Any]]]
StoreTokenHandler = Union[Callable[[Token], None], Callable[[Token], Awaitable[None]]]
