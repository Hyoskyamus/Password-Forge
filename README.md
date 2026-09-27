# Password Forge 🔐

A small command-line password and passphrase generator written in Python.

## Features

- Cryptographically secure randomness via `secrets`
- Configurable password length and quantity
- Lowercase, uppercase, digits and symbols
- Ambiguous-character exclusion
- Custom character exclusions
- Optional no-repeat mode
- Optional category enforcement
- Secure passphrase generation
- Standard-library only
- Automated unit tests

## Requirements

Python 3.10 or newer.

## Usage

Generate one password:

```bash
python password_forge.py password
```

Generate three 32-character passwords:

```bash
python password_forge.py password --length 32 --count 3
```

Avoid ambiguous characters:

```bash
python password_forge.py password --exclude-ambiguous
```

Generate a passphrase:

```bash
python password_forge.py passphrase --words 6 --separator "-"
```

## Security note

This project uses Python's `secrets` module rather than `random`.
Generated passwords should be copied into a password manager and should
not be committed to Git or posted publicly.

The entropy calculation is theoretical: it describes the size of the
configured random space and is not a guarantee of real-world security.

## Testing

Run:

```bash
python -m unittest -v
```

## License

MIT
