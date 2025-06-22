import time
from argparse import ArgumentParser
from sys import stdout

from otp.rfc.common import AllowedAlgorithms

from .otp import URIData, parse_uri, totp

parser = ArgumentParser(
    prog="OTP",
    description="Takes a URI for an HOTP or TOTP, and updates a display of the OTP code presently.",
    epilog="Copyright (C) Afam-Ifediogor, U. Divine.",
)
parser.add_argument(
    "URIs",
    nargs="*",
    type=str,
    help="The URIs for TOTPs",
)
parser.add_argument(
    "-r",
    "--refresh-interval",
    type=int,
    default=1,
    help="How often to refresh the OTP code display.",
)


def main():
    args = parser.parse_args()
    if not args.URIs:
        parser.print_help()
        return

    tokens: list[URIData] = [parse_uri(uri) for uri in args.URIs]
    print(tokens)
    try:
        while True:
            now = time.time()
            for token in tokens:
                remaining = token["period"] - int(now) % token["period"]

                code = totp(
                    secret=token["secret"],
                    digits=token["digits"],
                    period=token["period"],
                    algorithm=AllowedAlgorithms(token["algorithm"]),
                )
                message = (
                    f"\r{token['issuer'] or 'Unknown'} - {token['label']} ➡ "
                    f"{code} [{str(remaining).zfill(2)}s left]"
                )

                stdout.write("\r" + message)
                stdout.flush()
            time.sleep(args.refresh_interval)
    except KeyboardInterrupt:
        print("\nExiting.")


if __name__ == "__main__":
    main()
