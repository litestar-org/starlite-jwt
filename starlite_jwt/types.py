from typing import Any, Awaitable, Callable, Union

RetrieveUserHandler = Union[
    Callable[[str], Any],
    Callable[[str], Awaitable[Any]],
]
