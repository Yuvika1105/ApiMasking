"""
Dynamic Data Masking Sandbox — FastAPI Backend
================================================
Architecture : Decoupled Middleware (Plug-in / Plug-out)
Start        : uvicorn main:app --reload --port 8000
Docs         : http://127.0.0.1:8000/docs
Frontend     : http://127.0.0.1:8000/
"""

import json
import random
import requests
from typing import Any, List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# ── App instance ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="Dynamic Data Masking Microservice",
    description=(
        "End-to-end sandbox demonstrating decoupled dynamic data masking middleware "
        "using a Plug-in / Plug-out architecture with Microsoft Presidio and spaCy."
    ),
    version="2.0.0",
)

# ── CORS: allow the local HTML frontend to call these endpoints ───────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Serve the frontend (index.html) at / ─────────────────────────────────────
@app.get("/", include_in_schema=False)
async def serve_frontend():
    return FileResponse("index.html")


# ── Pydantic request/response models ─────────────────────────────────────────
class QueryRequest(BaseModel):
    prompt: str


class MaskRequest(BaseModel):
    raw_response: str


class SampleQuery(BaseModel):
    id: str
    label: str
    prompt: str
    description: str


# ── Presidio lazy singleton ───────────────────────────────────────────────────
_analyzer: AnalyzerEngine | None = None
_anonymizer: AnonymizerEngine | None = None


def _get_presidio():
    """
    Initialise the Presidio AnalyzerEngine (with spaCy en_core_web_sm) and
    AnonymizerEngine exactly once; reuse on every subsequent call.
    """
    global _analyzer, _anonymizer
    if _analyzer is None:
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()

        spacy_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        nlp_provider = NlpEngineProvider(nlp_configuration=spacy_config)
        nlp_engine = nlp_provider.create_engine()

        _analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
        _anonymizer = AnonymizerEngine()

    return _analyzer, _anonymizer


# ── Entity → tag mapping (Step 3) ────────────────────────────────────────────
PRESIDIO_ENTITIES = ["PERSON", "LOCATION", "ORGANIZATION"]

OPERATORS = {
    "PERSON":       OperatorConfig("replace", {"new_value": "<CLIENT_REPRESENTATIVE>"}),
    "LOCATION":     OperatorConfig("replace", {"new_value": "<MANUFACTURING_FACILITY>"}),
    "ORGANIZATION": OperatorConfig("replace", {"new_value": "<VEHICLE_MODEL>"}),
}


# ── Recursive format-agnostic masking helper (Step 3) ────────────────────────
def recursive_mask_data_structure(
    data: Any,
    analyzer: AnalyzerEngine,
    anonymizer: AnonymizerEngine,
    operators: dict,
    entities: list,
) -> Any:
    """
    Walk any combination of dicts / lists / strings and apply Presidio masking
    to every string value while leaving JSON structural keys untouched.
    """
    if isinstance(data, dict):
        return {
            k: recursive_mask_data_structure(v, analyzer, anonymizer, operators, entities)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [
            recursive_mask_data_structure(i, analyzer, anonymizer, operators, entities)
            for i in data
        ]
    elif isinstance(data, str):
        results = analyzer.analyze(text=data, language="en", entities=entities)
        return anonymizer.anonymize(
            text=data, analyzer_results=results, operators=operators
        ).text
    return data


# ── Pluggable masking interceptor (Step 4 — reusable for any service) ────────
def pluggable_masking_interceptor(
    raw_llm_payload: str,
    middleware_url: str = "http://127.0.0.1:8000/api/v1/mask",
) -> str:
    """
    Drop-in helper for any backend service that needs to run text through the
    masking middleware. Uses a strict try-except to guarantee a safe fallback
    when the masking engine is unreachable (timeout / crash / network issue).
    """
    if not raw_llm_payload or not raw_llm_payload.strip():
        return raw_llm_payload
    try:
        response = requests.post(
            middleware_url,
            json={"raw_response": raw_llm_payload},
            timeout=3.0,
        )
        response.raise_for_status()
        return response.json().get("masked_response", raw_llm_payload)
    except requests.exceptions.RequestException:
        return "Security Block: Response contained client details and could not be verified."


# ── Step 1 — Mock RAG Responses ───────────────────────────────────────────────
#
#  Multiple sensitive-data-rich payloads simulating real LLM/RAG production
#  output: client names, vehicle models, and manufacturing sites embedded.
#
MOCK_RAG_RESPONSES = {
    "q3_production": (
        "Based on the Q3 production analysis, our key account manager John Carter "
        "confirmed that the Windsor EV units allocated to the Halol Manufacturing Plant "
        "in Gujarat are on schedule. Furthermore, Sarah Mitchell from the regional compliance "
        "team flagged that Hector Plus deliveries destined for the Pune Assembly Facility "
        "require revised documentation before the 15th. The Astor batch assigned to the "
        "Bawal Plant is awaiting sign-off from David Reynolds, the lead logistics coordinator."
    ),
    "supplier": (
        "Supplier escalation report for Q3: Rajesh Verma (Tier-1 Procurement Lead) has flagged "
        "a critical shortage of powertrain components at the Pithampur Facility affecting "
        "Gloster production targets. Emily Chen from the global supply chain office confirms "
        "that alternate sourcing through the Vadodara Assembly Hub is being evaluated. "
        "Component buffers managed by Michael Torres at the Nasik Plant remain adequate "
        "for current ZS EV build rates through end of quarter."
    ),
    "compliance": (
        "Regulatory compliance summary: Anita Sharma (Head of Compliance, Central Region) "
        "has completed the audit of the Mandideep Plant covering Hector and Hector Plus "
        "models. James Whitfield, the external IATF auditor, noted that corrective actions "
        "from the Halol Plant review must be closed by 30th. Additionally, Priya Nair from "
        "the legal team has submitted the updated emissions declaration for the Astor "
        "variant produced at the Bawal Plant for final ministerial sign-off."
    ),
    "default": (
        "Based on the Q3 production analysis, our key account manager John Carter "
        "confirmed that the Windsor EV units allocated to the Halol Manufacturing Plant "
        "in Gujarat are on schedule. Furthermore, Sarah Mitchell from the regional compliance "
        "team flagged that Hector Plus deliveries destined for the Pune Assembly Facility "
        "require revised documentation before the 15th. The Astor batch assigned to the "
        "Bawal Plant is awaiting sign-off from David Reynolds, the lead logistics coordinator."
    ),
}

# ── Sample queries for the UI ─────────────────────────────────────────────────
SAMPLE_QUERIES: List[SampleQuery] = [
    SampleQuery(
        id="q3_production",
        label="Q3 Production Report",
        prompt="Show me the Q3 production allocation report",
        description="Allocation of EV models across manufacturing plants",
    ),
    SampleQuery(
        id="supplier",
        label="Supplier Escalation",
        prompt="Get the latest supplier escalation and procurement status",
        description="Tier-1 supplier shortage & alternate sourcing analysis",
    ),
    SampleQuery(
        id="compliance",
        label="Compliance Audit",
        prompt="Retrieve the regulatory compliance and audit summary",
        description="IATF audit findings and corrective action status",
    ),
]


def _select_response(prompt: str) -> str:
    """Route the prompt to the appropriate mock response based on keywords."""
    p = prompt.lower()
    if any(k in p for k in ["supplier", "procurement", "sourcing", "shortage"]):
        return MOCK_RAG_RESPONSES["supplier"]
    if any(k in p for k in ["compliance", "audit", "regulatory", "iatf"]):
        return MOCK_RAG_RESPONSES["compliance"]
    if any(k in p for k in ["q3", "production", "allocation", "report"]):
        return MOCK_RAG_RESPONSES["q3_production"]
    return MOCK_RAG_RESPONSES["default"]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/v1/queries/samples", response_model=List[SampleQuery])
async def get_sample_queries():
    """
    Returns the list of pre-built sample prompts for the UI demo panel.
    """
    return SAMPLE_QUERIES


@app.post("/api/v1/query")
async def mock_rag_query(request: QueryRequest):
    """
    Step 1 — Mock RAG endpoint.
    Mimics our LLM production stack by returning a sensitive hardcoded payload
    mapped to a 'raw_response' JSON key. Routes to one of 3 payloads based on
    the prompt keywords so different queries surface different sensitive data.
    """
    return {"raw_response": _select_response(request.prompt)}


@app.post("/api/v1/mask")
async def mask_response(request: MaskRequest):
    """
    Step 3 — Presidio-powered masking microservice.

    • Uses Microsoft Presidio + spaCy (en_core_web_sm) for NER-based entity tagging.
    • Format-agnostic: if the payload is valid JSON, recurse through values while
      leaving keys intact; otherwise treat as plain text.
    • Maps entity types to uppercase tags:
        PERSON       → <CLIENT_REPRESENTATIVE>
        LOCATION     → <MANUFACTURING_FACILITY>
        ORGANIZATION → <VEHICLE_MODEL>
    """
    analyzer, anonymizer = _get_presidio()

    raw = request.raw_response

    # Attempt to parse as JSON for recursive masking; fall back to plain text.
    try:
        parsed = json.loads(raw)
        masked_obj = recursive_mask_data_structure(
            parsed, analyzer, anonymizer, OPERATORS, PRESIDIO_ENTITIES
        )
        masked_text = json.dumps(masked_obj, indent=2)
    except (json.JSONDecodeError, ValueError):
        masked_text = recursive_mask_data_structure(
            raw, analyzer, anonymizer, OPERATORS, PRESIDIO_ENTITIES
        )

    return {"masked_response": masked_text}


@app.get("/health")
async def health():
    """Liveness probe — confirms the server is running."""
    return {"status": "ok", "service": "Dynamic Data Masking Microservice", "version": "2.0.0"}
