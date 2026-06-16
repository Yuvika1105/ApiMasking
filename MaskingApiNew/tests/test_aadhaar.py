import unittest
from safeguard.masker import mask

class TestAadhaarMasking(unittest.TestCase):
    def test_valid_aadhaar(self):
        # Using a mathematically valid Aadhaar format for testing
        text = "My aadhaar is 999999999910"
        result = mask(text)
        self.assertIn("<AADHAAR>", result)
        
    def test_invalid_aadhaar(self):
        text = "My aadhaar is 1234 5678 9012" # Invalid Verhoeff
        result = mask(text)
        self.assertNotIn("<AADHAAR>", result)

    def test_aadhaar_field_mask(self):
        data = {"aadhaar": "123456789012"}
        result = mask(data)
        self.assertEqual(result["aadhaar"], "123456789012") # Shouldn't mask invalid

if __name__ == '__main__':
    unittest.main()
