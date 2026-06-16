import unittest
from safeguard.masker import mask

class TestEmailMasking(unittest.TestCase):
    def test_email_masking(self):
        text = "Contact me at alice.smith@example.com"
        result = mask(text)
        self.assertNotIn("alice.smith@example.com", result)
        self.assertIn("a*********h@e*****e.com", result)

if __name__ == '__main__':
    unittest.main()
