import unittest
from safeguard.masker import mask

class TestNestedJsonMasking(unittest.TestCase):
    def test_nested_json(self):
        data = {
            "user": {
                "profile": {
                    "contact": "alice.smith@example.com",
                    "phone": "+1-555-234-5678"
                }
            },
            "history": [
                {"message": "Call +1-555-234-5678"}
            ]
        }
        result = mask(data)
        self.assertEqual(result["user"]["profile"]["contact"], "a*********h@e*****e.com")
        self.assertNotIn("555", result["user"]["profile"]["phone"])
        self.assertNotIn("555", result["history"][0]["message"])

if __name__ == '__main__':
    unittest.main()
