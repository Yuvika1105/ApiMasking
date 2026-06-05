# SafeGuard — Dynamic Data Masking Sandbox

End-to-end sandbox demonstrating **decoupled dynamic data masking middleware** using a **Plug-in / Plug-out** architecture.

## Architecture

```
Frontend (HTML/JS) → POST /api/v1/query (Mock RAG) → POST /api/v1/mask (Presidio) → User Display
```

| Layer | Technology |
|---|---|
| UI Gateway | HTML · Vanilla CSS · Async JavaScript |
| Mock RAG Backend | FastAPI · Python |
| Masking Microservice | Microsoft Presidio · spaCy `en_core_web_sm` |

## Entity Tag Mapping

| Presidio Entity | Output Tag |
|---|---|
| `PERSON` | `<CLIENT_REPRESENTATIVE>` |
| `LOCATION` | `<MANUFACTURING_FACILITY>` |
| `ORGANIZATION` | `<VEHICLE_MODEL>` |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn main:app --reload --port 8000
```

Then open **http://127.0.0.1:8000** in your browser.

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Frontend UI |
| `POST` | `/api/v1/query` | Mock RAG — returns sensitive payload |
| `POST` | `/api/v1/mask` | Presidio masking microservice |
| `GET` | `/api/v1/queries/samples` | Sample demo queries for UI |
| `GET` | `/health` | Liveness probe |
| `GET` | `/docs` | Swagger UI |
