from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

response = client.post(
    "/api/v1/mask",
    json={"raw_response": "Supplier escalation report for Q3", "custom_rules": []}
)

print("STATUS:", response.status_code)
print("BODY:", response.text)
