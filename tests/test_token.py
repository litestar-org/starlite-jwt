import string
from datetime import datetime, timedelta
from typing import Optional

from hypothesis import given
from hypothesis.strategies import none, one_of, sampled_from, text

from starlite_jwt_auth import Token


@given(
    algorithm=sampled_from(
        [
            "HS256",
            "HS384",
            "HS512",
        ]
    ),
    token_sub=text(min_size=1),
    token_secret=text(min_size=10),
    token_issuer=one_of(none(), text(max_size=256)),
    token_audience=one_of(none(), text(max_size=256, alphabet=string.ascii_letters)),
    token_unique_jwt_id=one_of(none(), text(max_size=256)),
)
def test_encode_decode(
    algorithm: str,
    token_sub: str,
    token_secret: str,
    token_issuer: Optional[str],
    token_audience: Optional[str],
    token_unique_jwt_id: Optional[str],
) -> None:
    token = Token(
        sub=token_sub,
        exp=(datetime.utcnow() + timedelta(seconds=30)),
        aud=token_audience,
        iss=token_issuer,
        jti=token_unique_jwt_id,
    )
    encoded_token = token.encode(secret=token_secret, algorithm=algorithm)
    decoded_token = token.decode(encoded_token=encoded_token, secret=token_secret, algorithm=algorithm)
    assert token.dict() == decoded_token.dict()
