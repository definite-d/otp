from .rfc.rfc_4226 import rfc_4226


def hotp():
    return rfc_4226()
