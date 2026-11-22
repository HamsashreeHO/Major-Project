"""Diagnostic codec probes for the published V0 sample; never asserts a format."""

from pathlib import Path

from v0 import (
    SUPPORTED_CODECS,
    PayloadError,
    decimal_to_big_integer_bytes,
    decompress_payload,
)


FIXTURE = Path(__file__).parent / "fixtures" / "official_sample_decimal.txt"


def main():
    decimal_payload = FIXTURE.read_text(encoding="ascii")
    encoded = decimal_to_big_integer_bytes(decimal_payload)
    print(f"Official sample digits: {len(''.join(decimal_payload.split()))}")
    print(f"BigInteger-style byte count: {len(encoded)}")

    successes = []
    for codec in SUPPORTED_CODECS:
        try:
            decoded = decompress_payload(encoded, codec)
        except PayloadError:
            print(f"{codec}: rejected")
        else:
            successes.append((codec, len(decoded)))
            print(f"{codec}: decompressed {len(decoded)} bytes")

    if not successes:
        print("No documented decompression rule could be applied; parsing and signature verification were not attempted.")
    else:
        print("A codec probe succeeded, but this is not evidence that UIDAI specifies that codec.")


if __name__ == "__main__":
    main()
