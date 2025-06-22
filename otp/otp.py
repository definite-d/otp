import hashlib
from enum import Enum


class AllowedAlgorithms(Enum):
    HMAC_SHA_1 = hashlib.sha1
    HMAC_SHA_256 = hashlib.sha256
    HMAC_SHA_512 = hashlib.sha512

# HOTP (RFC 4226) - https://www.ietf.org/rfc/rfc4226.txt
def _rfc_4226(C: bytes, K: bytes, Digit: int = 6, HMAC: AllowedAlgorithms = AllowedAlgorithms.HMAC_SHA_1) -> int:
    """
    Implementation of the HOTP algorithm, following RFC 4226
    (with the HMAC parameter being the only deviation from the spec).

    :param C:  8-byte counter value, the moving factor.
        This counter MUST be synchronized between the HOTP generator (client)
         and the HOTP validator (server).
    :param K: shared secret between client and server; each HOTP
        generator has a different and unique secret K.
    :param Digit: number of digits in an HOTP value; system parameter.
    :param HMAC: HOTP hash function; HMAC_SHA_1 by default, spec-compliant.
    :return D: D is a number in the range 0...10^{Digit}-1
    """

    # Validation
    if Digit < 6:
        raise ValueError('Digit must be >= 6')
    if HMAC not in AllowedAlgorithms:
        raise ValueError('HMAC must be one of: ' + ", ".join(AllowedAlgorithms))


def hotp():
    ...