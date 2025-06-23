from base64 import b32decode
from typing import TypedDict
from urllib.parse import parse_qs, unquote, urlparse

from .rfc.common import AllowedAlgorithms
from .rfc.rfc_4226 import rfc_4226
from .rfc.rfc_6238 import rfc_6238


class URIData(TypedDict):
    label: str
    secret: bytes
    issuer: str
    digits: int
    period: int
    algorithm: str


def hotp(secret: bytes, counter: int, digits=6) -> str:
    return rfc_4226(
        C=(counter.to_bytes(8, "big")),
        K=secret,
        Digit=digits,
        _HMAC_ALGORITHM=AllowedAlgorithms.HMAC_SHA_1,
    )


def totp(
    secret: bytes,
    digits: int = 6,
    period: int = 30,
    t0=0,
    algorithm: AllowedAlgorithms = AllowedAlgorithms.HMAC_SHA_1,
) -> str:
    return rfc_6238(K=secret, T0=t0, X=period, Digit=digits, algorithm=algorithm)


def parse_uri(uri: str) -> URIData:
    parsed = urlparse(uri)
    if parsed.scheme != "otpauth" or parsed.netloc != "totp":
        raise ValueError("Only TOTP URIs are supported.")

    label = unquote(parsed.path[1:])
    params = parse_qs(parsed.query)

    def get(key, default=None):
        return params.get(key, [default])[0]

    return URIData(
        label=label,
        secret=b32decode(get("secret").upper()),
        issuer=get("issuer"),
        digits=int(get("digits", 6)),
        period=int(get("period", 30)),
        algorithm=get("algorithm", AllowedAlgorithms.HMAC_SHA_256).lower(),
    )
