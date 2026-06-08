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
import re
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
    from fastapi.responses import HTMLResponse
    with open("index.html", "r", encoding="utf-8") as f:
        html = f.read()
    
    # Inject cache-busting redirect script right after <head>
    buster_script = """
    <script>
      if (!window.location.search.includes('v=')) {
          window.location.replace('/?v=' + new Date().getTime());
      }
    </script>
    """
    html = html.replace("<head>", "<head>\n" + buster_script, 1)
    
    response = HTMLResponse(content=html)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ── Pydantic request/response models ─────────────────────────────────────────
class QueryRequest(BaseModel):
    prompt: str


class CustomRule(BaseModel):
    """A user-defined word masking rule applied on top of Presidio."""
    pattern: str
    position: str = "prefix"       # "prefix" | "suffix" | "contains" | "exact"
    masking_type: str = "replace"  # "replace" | "first_last"
    replacement: str = "X"         # used only when masking_type == "replace"


class MaskRequest(BaseModel):
    raw_response: str
    custom_rules: List[CustomRule] = []


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
        try:
            import spacy
            import spacy.util
            if not spacy.util.is_package("en_core_web_sm"):
                spacy.cli.download("en_core_web_sm")
        except Exception as e:
            print(f"Failed to auto-download spaCy model: {e}")

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


# ── PII masking helper functions ──────────────────────────────────────────────

def _mask_name(text: str) -> str:
    """Show only first and last letter of each word: 'John Carter' → 'J**n C****r'."""
    parts = text.split()
    masked = []
    for part in parts:
        if len(part) <= 2:
            masked.append(part)
        else:
            masked.append(part[0] + '*' * (len(part) - 2) + part[-1])
    return ' '.join(masked)



def _mask_phone(text: str) -> str:
    """Show only last 3 digits, replace rest with X: '9876543210' → 'XXXXXXX210'."""
    digits = re.sub(r'\D', '', text)
    if not digits or len(digits) <= 3:
        return 'X' * len(text)
    show_from = len(digits) - 3
    digit_idx = 0
    result = []
    for ch in text:
        if ch.isdigit():
            result.append(ch if digit_idx >= show_from else 'X')
            digit_idx += 1
        else:
            result.append(ch)
    return ''.join(result)


def _mask_email(text: str) -> str:
    """Mask email keeping first & last char of local+domain: 'john@gmail.com' → 'j**n@g**l.com'."""
    try:
        local, domain = text.split('@', 1)
        d_parts = domain.rsplit('.', 1)
        d_name = d_parts[0]
        d_ext = d_parts[1] if len(d_parts) > 1 else ''

        def _partial(s: str) -> str:
            if len(s) <= 1:
                return s
            if len(s) == 2:
                return s[0] + '*'
            return s[0] + '*' * (len(s) - 2) + s[-1]

        return f"{_partial(local)}@{_partial(d_name)}.{d_ext}"
    except Exception:
        return '***@***.***'


# ── Entity → tag mapping (Step 3) ────────────────────────────────────────────
PRESIDIO_ENTITIES = ["PERSON", "LOCATION", "ORGANIZATION", "PHONE_NUMBER", "EMAIL_ADDRESS"]

OPERATORS = {
    "PERSON":        OperatorConfig("custom", {"lambda": _mask_name}),
    "LOCATION":      OperatorConfig("replace", {"new_value": "<MANUFACTURING_FACILITY>"}),
    "ORGANIZATION":  OperatorConfig("replace", {"new_value": "<VEHICLE_MODEL>"}),
    "PHONE_NUMBER":  OperatorConfig("custom", {"lambda": _mask_phone}),
    "EMAIL_ADDRESS": OperatorConfig("custom", {"lambda": _mask_email}),
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


# ── Custom word rules (Step 4) ───────────────────────────────────────────────

def apply_custom_rules(text: str, rules: List[CustomRule]) -> str:
    """
    Apply user-defined word masking rules on top of Presidio output.
    Each rule specifies:
      - pattern   : the word/prefix/suffix to match
      - position  : prefix / suffix / contains / exact
      - masking_type:
            "replace"    -> substitute matched token with rule.replacement (e.g. "X")
            "first_last" -> keep only first + last character of matched token
                            e.g. "Astor" -> "Ar", "Windsor" -> "Wr"
    """
    for rule in rules:
        pat = re.escape(rule.pattern)

        # Build the masking callable
        if rule.masking_type == "first_last":
            def _repl(m, _=None):
                s = m.group(0)
                return (s[0] + s[-1]) if len(s) > 1 else s
        else:
            _rep = rule.replacement or "X"
            def _repl(m, r=_rep):
                return r

        try:
            if rule.position == "prefix":
                text = re.sub(rf'(?<!\S){pat}\S*', _repl, text, flags=re.IGNORECASE)
            elif rule.position == "suffix":
                text = re.sub(rf'\S*{pat}(?!\S)', _repl, text, flags=re.IGNORECASE)
            elif rule.position == "contains":
                text = re.sub(rf'\S*{pat}\S*', _repl, text, flags=re.IGNORECASE)
            else:  # exact
                text = re.sub(rf'(?<!\S){pat}(?!\S)', _repl, text, flags=re.IGNORECASE)
        except re.error:
            pass  # skip malformed patterns gracefully
    return text


# ── Pluggable masking interceptor (Step 5 — reusable for any service) ────────
def pluggable_masking_interceptor(
    raw_llm_payload: str,
    middleware_url: str = "http://127.0.0.1:8000/api/v1/mask",
) -> str:
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
    return {"raw_response": _select_response(request.prompt)}


@app.post("/api/v1/mask")
async def mask_response(request: MaskRequest):
    """
    Step 3 — Presidio-powered masking microservice.

    • Uses Microsoft Presidio + spaCy (en_core_web_sm) for NER-based entity tagging.
    • Format-agnostic: if the payload is valid JSON, recurse through values while
      leaving keys intact; otherwise treat as plain text.
    • Masking strategies per entity type:
        PERSON        → First & last letter only  (J**n C****r)
        PHONE_NUMBER  → Last 3 digits visible     (XXXXXXX210)
        EMAIL_ADDRESS → Partial mask              (j***n@g**l.com)
        LOCATION      → <MANUFACTURING_FACILITY>
        ORGANIZATION  → <VEHICLE_MODEL>
    • Optional custom_rules are applied on top of Presidio output (Step 4).
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

    # Step 4 — Apply user-defined custom word rules on top of Presidio output
    if request.custom_rules:
        masked_text = apply_custom_rules(masked_text, request.custom_rules)

    return {"masked_response": masked_text}


@app.get("/health")
async def health():
    """Liveness probe — confirms the server is running."""
    return {"status": "ok", "service": "Dynamic Data Masking Microservice", "version": "2.0.0"}
