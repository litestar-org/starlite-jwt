from datetime import datetime
from typing import Optional, Union
from uuid import UUID

from jose import JWTError, jwt
from pydantic import BaseModel, Field, ValidationError
from starlite import ImproperlyConfiguredException
from starlite.exceptions import NotAuthorizedException


class Token(BaseModel):
    """This class represents a JWT token."""

    exp: datetime
    """Expiration - datetime for token expiration."""
    iat: datetime = Field(default_factory=datetime.now, const=True)
    """Issued at - should always be current now."""
    sub: Union[UUID, str]
    """Subject - usually a unique identifier of the user or equivalent entity."""
    iss: Optional[str] = None
    """Issuer - optional unique identifier for the issuer."""
    aud: Optional[str] = None
    """Audience - intended audience."""
    jti: Optional[str] = None
    """JWT ID - a unique identifier of the JWT between different issuers."""

    @staticmethod
    def decode(encoded_token: str, secret: str, algorithm: str) -> "Token":
        """Decodes a passed in token string and returns a Token instance.

        Args:
            encoded_token: A base64 string containing an encoded JWT.
            secret: The secret with which the JWT is encoded.
            algorithm: The algorithm used to encode the JWT.

        Returns:
            A decoded Token instance.

        Raises:
            [NotAuthorizedException][starlite.exceptions.NotAuthorizedException]: If token is invalid.
        """
        try:
            payload = jwt.decode(token=encoded_token, key=secret, algorithms=[algorithm])
            return Token(**payload)
        except (JWTError, ValidationError) as e:
            raise NotAuthorizedException("Invalid token") from e

    def encode(self, secret: str, algorithm: str) -> str:
        """Encodes the token instance into a string.

        Args:
            secret: The secret with which the JWT is encoded.
            algorithm: The algorithm used to encode the JWT.

        Returns:
            An encoded token string.

        Raises:
            [ImproperlyConfiguredException][starlite.exceptions.ImproperlyConfiguredException]: If encoding fails.
        """
        try:
            return jwt.encode(claims=self.dict(exclude_none=True), key=secret, algorithm=algorithm)
        except JWTError as e:
            raise ImproperlyConfiguredException("Failed to encode token") from e
