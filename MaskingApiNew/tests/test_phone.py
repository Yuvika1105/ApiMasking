import unittest
from safeguard.masker import mask

class TestPhoneMasking(unittest.TestCase):
    def test_phone_masking(self):
        text = "Call me at +1-555-234-5678"
        result = mask(text)
        self.assertNotIn("+1-555-234-5678", result)
        self.assertNotIn("555", result)

if __name__ == '__main__':
    unittest.main()
