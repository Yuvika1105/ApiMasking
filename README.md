# SafeGuard — Dynamic Data Masking Sandbox

End-to-end sandbox demonstrating **decoupled dynamic data masking middleware** using a **Plug-in / Plug-out** architecture. The core masking engine has been refactored into a standalone Python package that can be imported directly into your data pipelines.

## 📦 Using as a Standalone Package (Backend & Pipelines)

You can install the `safeguard` package directly from this repository and use it in any Python backend (Flask, Celery, scripts, etc.) without needing the FastAPI server.

### Installation

```bash
# Install the core package directly from the directory
pip install .

# Or, if installing from a Git repository:
pip install git+https://github.com/yourusername/safeguard.git
```

### Usage

```python
from safeguard.masker import SafeGuardMasker

# 1. Instantiate the masker (NLP models load once here)
masker = SafeGuardMasker()

# 2. Prepare your data (string, list, or dict)
sensitive_data = {
    "user_id": 12345,
    "profile": {
        "name": "John Carter",
        "contact": {
            "email": "john.carter@example.com",
            "phone": "9876543210"
        }
    },
    "location": "Halol Manufacturing Plant"
}

# 3. Mask the data! The exact JSON structure is preserved.
masked_data = masker.mask(sensitive_data)

import json
print(json.dumps(masked_data, indent=2))
```

**Output:**
```json
{
  "user_id": 12345,
  "profile": {
    "name": "J**n C****r",
    "contact": {
      "email": "j***n@e*****e.com",
      "phone": "XXXXXXX210"
    }
  },
  "location": "<MANUFACTURING_FACILITY>"
}
```

---

## 🌐 Running the Sandbox API Server

The original FastAPI application uses the `safeguard` package under the hood.

### Quick Start

```bash
# Install with API dependencies
pip install .[api]

# Start the server
uvicorn main:app --reload --port 8000
```

Then open **http://127.0.0.1:8000** in your browser.

## Architecture

```
Frontend (HTML/JS) → POST /api/v1/query (Mock RAG) → POST /api/v1/mask (SafeGuard Package) → User Display
```

| Layer | Technology |
|---|---|
| UI Gateway | HTML · Vanilla CSS · Async JavaScript |
| Mock RAG Backend | FastAPI · Python |
| Masking Package (`safeguard`) | Microsoft Presidio · spaCy `en_core_web_sm` |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Frontend UI |
| `POST` | `/api/v1/query` | Mock RAG — returns sensitive payload |
| `POST` | `/api/v1/mask` | Presidio masking microservice |
| `GET` | `/api/v1/queries/samples` | Sample demo queries for UI |
| `GET` | `/health` | Liveness probe |
| `GET` | `/docs` | Swagger UI |
