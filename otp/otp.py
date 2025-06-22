from .rfc.common import AllowedAlgorithms
from .rfc.rfc_4226 import rfc_4226


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
    algorithm: AllowedAlgorithms = AllowedAlgorithms.HMAC_SHA_256,
) -> str: ...
