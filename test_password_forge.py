import string
import unittest

from password_forge import (
    DEFAULT_SYMBOLS,
    build_alphabet,
    entropy_bits,
    generate_passphrase,
    generate_password,
)


class PasswordForgeTests(unittest.TestCase):
    def test_default_password_has_all_categories(self):
        password = generate_password(24)
        self.assertTrue(any(c in string.ascii_lowercase for c in password))
        self.assertTrue(any(c in string.ascii_uppercase for c in password))
        self.assertTrue(any(c in string.digits for c in password))
        self.assertTrue(any(c in DEFAULT_SYMBOLS for c in password))

    def test_length(self):
        self.assertEqual(len(generate_password(32)), 32)

    def test_exclusions(self):
        alphabet = build_alphabet(exclude="abcXYZ123")
        self.assertFalse(any(c in alphabet for c in "abcXYZ123"))

    def test_ambiguous_exclusion(self):
        alphabet = build_alphabet(exclude_ambiguous=True)
        self.assertFalse(any(c in alphabet for c in "O0oIl1|`'\""))

    def test_no_repeats(self):
        password = generate_password(30, no_repeats=True)
        self.assertEqual(len(password), len(set(password)))
        self.assertTrue(any(c in string.ascii_lowercase for c in password))
        self.assertTrue(any(c in string.ascii_uppercase for c in password))
        self.assertTrue(any(c in string.digits for c in password))
        self.assertTrue(any(c in DEFAULT_SYMBOLS for c in password))

    def test_no_repeats_small_valid_length(self):
        password = generate_password(4, no_repeats=True)
        self.assertEqual(len(password), 4)
        self.assertEqual(len(password), len(set(password)))

    def test_short_password_rejected(self):
        with self.assertRaises(ValueError):
            generate_password(3)

    def test_no_repeat_capacity(self):
        with self.assertRaises(ValueError):
            generate_password(1000, no_repeats=True)

    def test_passphrase(self):
        phrase = generate_passphrase(5, separator=".")
        self.assertEqual(len(phrase.split(".")), 5)

    def test_entropy(self):
        self.assertAlmostEqual(entropy_bits(2, 10), 10.0)

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            generate_password(0)
        with self.assertRaises(ValueError):
            generate_passphrase(1)


if __name__ == "__main__":
    unittest.main()
