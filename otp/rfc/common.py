from enum import StrEnum


class AllowedAlgorithms(StrEnum):
    HMAC_SHA_1 = "sha1"
    HMAC_SHA_256 = "sha256"
    HMAC_SHA_512 = "sha512"
