from .rfc.common import AllowedAlgorithms
from .rfc.rfc_4226 import rfc_4226


def hotp(secret: bytes, counter: int, digits=6) -> str:
    return rfc_4226(
        C=(counter.to_bytes(8, "big")),
        K=secret,
        Digit=digits,
        _HMAC_ALGORITHM=AllowedAlgorithms.HMAC_SHA_1,
    )
