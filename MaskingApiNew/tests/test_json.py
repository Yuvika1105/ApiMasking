import unittest
import json
from safeguard.masker import mask

class TestJsonMasking(unittest.TestCase):
    def test_json_string(self):
        json_str = '{"email": "bob@example.com"}'
        result = mask(json_str)
        self.assertNotIn("bob@example.com", result)
        self.assertIn("b*b@e*****e.com", result)

    def test_dict(self):
        data = {"email": "bob@example.com"}
        result = mask(data)
        self.assertEqual(result["email"], "b*b@e*****e.com")

if __name__ == '__main__':
    unittest.main()
