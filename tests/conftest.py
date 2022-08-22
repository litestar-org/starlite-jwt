from uuid import UUID

import pytest
from pydantic import BaseModel
from pydantic_factories import ModelFactory
from starlite.cache.simple_cache_backend import SimpleCacheBackend


class User(BaseModel):
    name: str
    id: UUID


class UserFactory(ModelFactory[User]):
    __model__ = User


@pytest.fixture(scope="module")
def mock_db() -> SimpleCacheBackend:
    return SimpleCacheBackend()
