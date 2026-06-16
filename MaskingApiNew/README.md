# SafeGuard PII Masker

An Enterprise Python package that automatically detects and masks Personally Identifiable Information (PII) like Names, Emails, Phone Numbers, Aadhaar, PAN, and Locations in your chatbot or API responses.

## Quick Start

### 1. Install
Install the package directly from source (this automatically downloads the required spaCy model):
```bash
pip install -e .
```

### 2. Configuration (Optional)
You can configure the masker once at startup. Different teams can set different allowlists or confidence thresholds.

```python
from safeguard import configure

configure(
    allowlist=["OpenAI", "Microsoft"],
    threshold=0.7,
    mode="accurate" # or "fast" for regex-only mode without NLP overhead
)
```

### 3. Usage

#### Option A: One-line Function Call
Easily mask any dictionary, list, string, or database row:

```python
from safeguard import mask

# Masking Chatbot Outputs
response = llm.invoke(prompt)
safe_response = mask(response)

# Masking API Responses or Database Rows
rows = db.fetch_all()
safe_rows = mask(rows)

# With a Report
safe_data = mask(json_data, return_report=True)
print(safe_data["entity_types"]) # {"PERSON": 1, "AADHAAR": 1}
```

#### Option B: Automatic Decorator
Add `@mask_output` above the function that returns your bot's response. The masking will happen automatically before the data is returned!

```python
from safeguard import mask_output

@mask_output
def get_bot_reply(prompt):
    return call_your_llm(prompt) # Returns raw PII
```

#### Option C: FastAPI Middleware
Zero-code integration for REST APIs:

```python
from fastapi import FastAPI
from safeguard import SafeGuardMiddleware

app = FastAPI()
app.add_middleware(SafeGuardMiddleware)
```
*(Note: Token Streaming responses are safely skipped to avoid breaking your stream.)*

## Features
- **Works with any format:** Accepts plain text, deeply nested JSON dicts, lists, and SQL query rows.
- **Enterprise Entities:** Includes custom mathematical validation for Aadhaar (Verhoeff checksum), contextual PAN detection, Employee IDs, VINs, and default Presidio entities.
- **Field-Aware Masking:** Safely target specific dictionary keys (like `customer_name`) for pinpoint masking without losing structural data.
- **Developer Toggle:** Set `SAFEGUARD_ENABLED=false` as an environment variable to disable masking temporarily.
