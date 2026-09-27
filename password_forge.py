#!/usr/bin/env python3
"""Secure password and passphrase generator.

Uses Python's `secrets` module for cryptographically secure randomness.
"""

from __future__ import annotations

import argparse
import math
import secrets
import string
from typing import Iterable

AMBIGUOUS = "O0oIl1|`'\""
DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
DEFAULT_WORDS = (
    "anchor", "apple", "autumn", "beacon", "birch", "canyon", "cedar",
    "comet", "coral", "cosmos", "crystal", "ember", "falcon", "forest",
    "galaxy", "harbor", "hazel", "jaguar", "lantern", "maple", "meadow",
    "meteor", "nebula", "ocean", "orchid", "otter", "pepper", "planet",
    "quartz", "river", "rocket", "saffron", "shadow", "silver", "sparrow",
    "sunset", "thunder", "tiger", "valley", "violet", "willow", "winter",
)


def build_alphabet(
    *,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: str = DEFAULT_SYMBOLS,
    exclude_ambiguous: bool = False,
    exclude: str = "",
) -> str:
    """Build and validate the character alphabet."""
    parts: list[str] = []
    if lowercase:
        parts.append(string.ascii_lowercase)
    if uppercase:
        parts.append(string.ascii_uppercase)
    if digits:
        parts.append(string.digits)
    if symbols:
        parts.append(symbols)

    alphabet = "".join(dict.fromkeys("".join(parts)))

    if exclude_ambiguous:
        alphabet = "".join(c for c in alphabet if c not in AMBIGUOUS)

    if exclude:
        alphabet = "".join(c for c in alphabet if c not in set(exclude))

    if not alphabet:
        raise ValueError("The resulting alphabet is empty.")

    return alphabet


def _require_categories(
    password: str,
    *,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: str,
) -> None:
    """Ensure a generated password contains each requested character class."""
    checks: list[tuple[bool, Iterable[str]]] = [
        (lowercase, string.ascii_lowercase),
        (uppercase, string.ascii_uppercase),
        (digits, string.digits),
        (bool(symbols), symbols),
    ]
    for enabled, chars in checks:
        if enabled and not any(c in chars for c in password):
            raise RuntimeError("Internal error: a requested category is missing.")


def generate_password(
    length: int = 20,
    *,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: str = DEFAULT_SYMBOLS,
    exclude_ambiguous: bool = False,
    exclude: str = "",
    no_repeats: bool = False,
    require_each: bool = True,
) -> str:
    """Generate one cryptographically secure password."""
    if length < 1:
        raise ValueError("Password length must be at least 1.")

    alphabet = build_alphabet(
        lowercase=lowercase,
        uppercase=uppercase,
        digits=digits,
        symbols=symbols,
        exclude_ambiguous=exclude_ambiguous,
        exclude=exclude,
    )

    requested = []
    if lowercase:
        requested.append(string.ascii_lowercase)
    if uppercase:
        requested.append(string.ascii_uppercase)
    if digits:
        requested.append(string.digits)
    if symbols:
        requested.append(symbols)

    if no_repeats and length > len(alphabet):
        raise ValueError(
            f"Cannot generate {length} unique characters from an alphabet "
            f"of {len(alphabet)} characters."
        )

    if require_each and length < len(requested):
        raise ValueError(
            f"Length {length} is too short to include all "
            f"{len(requested)} requested character categories."
        )

    if no_repeats:
        # Pick one character from each requested category first, then fill
        # the remaining positions from the unused alphabet.
        password_chars: list[str] = []
        used: set[str] = set()

        if require_each:
            for category in requested:
                choices = [c for c in category if c in alphabet and c not in used]
                if not choices:
                    raise ValueError(
                        "Cannot satisfy the requested categories without repeats."
                    )
                chosen = secrets.choice(choices)
                password_chars.append(chosen)
                used.add(chosen)

        remaining = [c for c in alphabet if c not in used]
        for _ in range(length - len(password_chars)):
            index = secrets.randbelow(len(remaining))
            password_chars.append(remaining.pop(index))

        secrets.SystemRandom().shuffle(password_chars)
        password = "".join(password_chars)
    else:
        password = "".join(secrets.choice(alphabet) for _ in range(length))

        if require_each:
            password_chars = list(password)
            for i, category in enumerate(requested):
                if not any(c in category for c in password_chars):
                    password_chars[i] = secrets.choice(
                        [c for c in category if c in alphabet]
                    )
            secrets.SystemRandom().shuffle(password_chars)
            password = "".join(password_chars)

    if require_each:
        _require_categories(
            password,
            lowercase=lowercase,
            uppercase=uppercase,
            digits=digits,
            symbols=symbols,
        )

    return password


def generate_passphrase(
    words: int = 5,
    *,
    separator: str = "-",
    wordlist: tuple[str, ...] = DEFAULT_WORDS,
    capitalize: bool = False,
    add_number: bool = False,
) -> str:
    """Generate a secure passphrase from a local word list."""
    if words < 2:
        raise ValueError("A passphrase must contain at least 2 words.")
    if not wordlist:
        raise ValueError("The word list cannot be empty.")

    selected = [secrets.choice(wordlist) for _ in range(words)]
    if capitalize:
        selected = [word.capitalize() for word in selected]

    phrase = separator.join(selected)
    if add_number:
        phrase += str(secrets.randbelow(100))

    return phrase


def entropy_bits(alphabet_size: int, length: int) -> float:
    """Return theoretical entropy in bits for uniform random selection."""
    if alphabet_size < 1:
        raise ValueError("Alphabet size must be positive.")
    if length < 1:
        raise ValueError("Length must be positive.")
    return length * math.log2(alphabet_size)


def password_entropy(password: str, alphabet: str) -> float:
    """Estimate entropy using the supplied alphabet size and password length."""
    return entropy_bits(len(alphabet), len(password))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate secure passwords and passphrases."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    pwd = subparsers.add_parser("password", help="Generate passwords.")
    pwd.add_argument("-l", "--length", type=int, default=20)
    pwd.add_argument("-n", "--count", type=int, default=1)
    pwd.add_argument("--no-lowercase", action="store_true")
    pwd.add_argument("--no-uppercase", action="store_true")
    pwd.add_argument("--no-digits", action="store_true")
    pwd.add_argument("--no-symbols", action="store_true")
    pwd.add_argument("--symbols", default=DEFAULT_SYMBOLS)
    pwd.add_argument("--exclude-ambiguous", action="store_true")
    pwd.add_argument("--exclude", default="")
    pwd.add_argument("--no-repeats", action="store_true")
    pwd.add_argument("--no-require-each", action="store_true")

    phrase = subparsers.add_parser("passphrase", help="Generate passphrases.")
    phrase.add_argument("-w", "--words", type=int, default=5)
    phrase.add_argument("-n", "--count", type=int, default=1)
    phrase.add_argument("--separator", default="-")
    phrase.add_argument("--capitalize", action="store_true")
    phrase.add_argument("--add-number", action="store_true")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.count < 1:
        parser.error("--count must be at least 1.")

    try:
        if args.mode == "password":
            for _ in range(args.count):
                print(
                    generate_password(
                        length=args.length,
                        lowercase=not args.no_lowercase,
                        uppercase=not args.no_uppercase,
                        digits=not args.no_digits,
                        symbols="" if args.no_symbols else args.symbols,
                        exclude_ambiguous=args.exclude_ambiguous,
                        exclude=args.exclude,
                        no_repeats=args.no_repeats,
                        require_each=not args.no_require_each,
                    )
                )
        else:
            for _ in range(args.count):
                print(
                    generate_passphrase(
                        words=args.words,
                        separator=args.separator,
                        capitalize=args.capitalize,
                        add_number=args.add_number,
                    )
                )
    except ValueError as exc:
        parser.error(str(exc))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
