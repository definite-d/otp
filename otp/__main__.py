import time
from argparse import ArgumentParser
from sys import stdout

from .otp import AllowedAlgorithms, URIData, parse_uri, totp

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
parser.add_argument(
    "-a",
    "--algorithm",
    choices=AllowedAlgorithms,
    help="The algorithm to use. Overrides any found in the URIs.",
    default=None,
)


def main():
    args = parser.parse_args()
    if not args.URIs:
        parser.print_help()
        return

    tokens: list[URIData] = [parse_uri(uri) for uri in args.URIs]
    try:
        past_first_iteration = False
        while True:
            now = time.time()
            messages = []
            for token in tokens:
                remaining = token["period"] - int(now) % token["period"]

                code = totp(
                    secret=token["secret"],
                    digits=token["digits"],
                    period=token["period"],
                    algorithm=args.algorithm or AllowedAlgorithms(token["algorithm"]),
                )
                messages.append(
                    f"{token['issuer'] or 'Unknown'} - {token['label']} ➡ "
                    f"{code} [{str(remaining).zfill(2)}s left]"
                )

            if past_first_iteration:
                for _ in range(len(tokens)):
                    stdout.write("\033[2K")  # Clear line from cursor to end
                    stdout.write("\033[F")  # Move cursor up one line
            else:
                past_first_iteration = True
            stdout.write("\n".join(messages))
            stdout.write("\n")
            stdout.flush()
            time.sleep(args.refresh_interval)
    except KeyboardInterrupt:
        print("\nExiting.")


if __name__ == "__main__":
    main()
