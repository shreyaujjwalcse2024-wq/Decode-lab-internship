"""
Basic tests for password_checker.py
Run with: python test_password_checker.py
"""

import unittest
from password_checker import score_password


class TestPasswordChecker(unittest.TestCase):

    def test_common_password_is_weak(self):
        strength, _ = score_password("password")
        self.assertEqual(strength, "Weak")

    def test_short_password_is_weak(self):
        strength, _ = score_password("Ab1!")
        self.assertEqual(strength, "Weak")

    def test_sequential_pattern_is_weak(self):
        strength, _ = score_password("Abcdefgh1!")
        self.assertEqual(strength, "Weak")

    def test_low_variety_is_weak(self):
        strength, _ = score_password("lowercaseonly")
        self.assertEqual(strength, "Weak")

    def test_decent_but_short_is_medium(self):
        strength, _ = score_password("Tulip9!fox")
        self.assertEqual(strength, "Medium")

    def test_long_varied_is_strong(self):
        strength, _ = score_password("Str0ng&Pass!2026")
        self.assertEqual(strength, "Strong")


if __name__ == "__main__":
    unittest.main()
