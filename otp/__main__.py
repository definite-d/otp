from .otp import totp
from argparse import ArgumentParser

parser = ArgumentParser(
    prog="OTP",
    description="Takes a URI for an HOTP or TOTP, and updates a display of the OTP code presently.",
    epilog="Copyright (C) Afam-Ifediogor, U. Divine.",
)
parser.add_argument(
    "URI",
    metavar="URI",
    nargs="?",
    type=str,
    help="The URI for an HOTP or TOTP",
)
parser.add_argument(
    "-r",
    "--refresh-interval",
    type=int,
    default=1,
    help="How often to refresh the OTP code display.",
)

if __name__ == "__main__":
    ...
