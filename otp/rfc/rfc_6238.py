import time
from typing import Union

from .common import AllowedAlgorithms
from .rfc_4226 import rfc_4226


# TOTP (RFC 6238) - https://datatracker.ietf.org/doc/html/rfc6238
# noinspection PyPep8Naming
def rfc_6238(
    K: bytes,
    T0: int = 0,
    X: int = 30,
    Digit: int = 6,
    algorithm: (
        Union[AllowedAlgorithms.HMAC_SHA_256, AllowedAlgorithms.HMAC_SHA_512]
    ) = AllowedAlgorithms.HMAC_SHA_256,
) -> str:
    """
    Basically, we define TOTP as TOTP = HOTP(K, T), where T is an integer
    and represents the number of time steps between the initial counter
    time T0 and the current Unix time.

    More specifically, T = (Current Unix time - T0) / X, where the
    default floor function is used in the computation.

    For example, with T0 = 0 and Time Step X = 30, T = 1 if the current
    Unix time is 59 seconds, and T = 2 if the current Unix time is
    60 seconds.

    :param T0: T0 is the Unix time to start counting time steps (default value is
      0, i.e., the Unix epoch) and is also a system parameter.
    :param X: X represents the time step in seconds (default value X =
      30 seconds) and is a system parameter.
    :param K: K represents the shared secret; see [RFC4226].
    :param Digit: How many digits to use; see [RFC4226].
    :param algorithm: The algorithm to use; may be HMAC_SHA_256 or HMAC_SHA_512.
    :return: A string representing the TOTP.
    """
    T = int((time.time() - T0) // X)
    return rfc_4226(T.to_bytes(length=8, byteorder="big"), K, Digit, algorithm)
