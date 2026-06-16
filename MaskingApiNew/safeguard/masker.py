# ============================================================
# safeguard/masker.py
#
# Auto PII Masking Engine
# 
# Requires: 
#   pip install presidio-analyzer presidio-anonymizer spacy
#   python -m spacy download en_core_web_lg
#
# ── HOW TO USE ──────────────────────────────────────────────
#
# OPTION A — Automatic Decorator
#   from safeguard.masker import mask_output
#
#   @mask_output
#   def get_bot_reply(prompt):
#       return call_your_llm(prompt)
#
# OPTION B — Manual Function
#   from safeguard.masker import mask
#
#   safe_response = mask(your_bot_response)
#   
#   # Or with a report:
#   safe_data = mask(your_bot_response, return_report=True)
#
# OPTION C — FastAPI Middleware
#   from safeguard.masker import SafeGuardMiddleware
#   app.add_middleware(SafeGuardMiddleware)
# ============================================================

import asyncio
import functools
import json
import os
import re
import threading
from typing import Any, Callable, List, Dict, Tuple, Optional

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# Try to import Starlette for Middleware support
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
    from starlette.types import ASGIApp
    STARLETTE_AVAILABLE = True
except ImportError:
    STARLETTE_AVAILABLE = False


# ── Middleware toggle ────────────────────────────────────────
MASKING_ENABLED: bool = os.environ.get("SAFEGUARD_ENABLED", "true").lower() != "false"

# ── Verhoeff Checksum for Aadhaar Validation ─────────────────
_d = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
)
_p = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8)
)

def validate_aadhaar(text: str) -> bool:
    c = 0
    num = text.replace(' ', '')
    if len(num) != 12 or not num.isdigit():
        return False
    inv_array = [int(n) for n in num][::-1]
    for i in range(len(inv_array)):
        c = _d[c][_p[i % 8][inv_array[i]]]
    return c == 0


# ============================================================
# SafeGuardMasker — the core masking class
# ============================================================

class SafeGuardMasker:
    """
    Masks PII in any string, dict, or list using Microsoft Presidio.
    """

    DEFAULT_ENTITIES = [
        "PERSON", "LOCATION", "ORGANIZATION", "PHONE_NUMBER", "EMAIL_ADDRESS",
        "CREDIT_CARD", "US_PASSPORT", "IP_ADDRESS", "US_BANK_NUMBER",
        "US_DRIVER_LICENSE", "URL", "AADHAAR", "PAN_CARD", "VIN", "EMPLOYEE_ID"
    ]

    def __init__(
        self, 
        score_threshold: float = 0.7, 
        field_masks: Dict[str, str] = None,
        allowlist: List[str] = None,
        mode: str = "accurate"  # "accurate" or "fast"
    ):
        self.score_threshold = score_threshold
        self.field_masks = {k.lower(): v for k, v in (field_masks or {}).items()}
        self.allowlist = [w.lower() for w in (allowlist or [])]
        self.mode = mode

        # Validate spaCy model installation if in accurate mode
        if self.mode == "accurate":
            try:
                import spacy.util
                if not spacy.util.is_package("en_core_web_lg"):
                    raise RuntimeError("Model 'en_core_web_lg' not found. Please install it using: python -m spacy download en_core_web_lg")
            except ImportError:
                raise RuntimeError("spaCy is not installed. Please install it via pip.")

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()

        # Add Custom Recognizers
        aadhaar_recognizer = PatternRecognizer(
            supported_entity="AADHAAR",
            patterns=[Pattern("AADHAAR", r"\b\d{4}\s?\d{4}\s?\d{4}\b", 0.8)]
        )
        pan_recognizer = PatternRecognizer(
            supported_entity="PAN_CARD",
            patterns=[Pattern("PAN_CARD", r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", 0.8)],
            context=["pan", "permanent account number"]
        )
        vin_recognizer = PatternRecognizer(
            supported_entity="VIN",
            patterns=[Pattern("VIN", r"\b[A-HJ-NPR-Z0-9]{17}\b", 0.8)]
        )
        employee_id_recognizer = PatternRecognizer(
            supported_entity="EMPLOYEE_ID",
            patterns=[Pattern("EMPLOYEE_ID", r"\b(?:EMP|ID)-?\d{4,8}\b", 0.6)]
        )
        phone_recognizer = PatternRecognizer(
            supported_entity="PHONE_NUMBER",
            patterns=[Pattern("PHONE_NUMBER", r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}\b", 0.7)]
        )

        registry.add_recognizer(aadhaar_recognizer)
        registry.add_recognizer(pan_recognizer)
        registry.add_recognizer(vin_recognizer)
        registry.add_recognizer(employee_id_recognizer)
        registry.add_recognizer(phone_recognizer)

        # Validate that default entities exist in the registry
        loaded_recognizers = registry.recognizers
        supported_entities = set()
        for rec in loaded_recognizers:
            supported_entities.update(rec.supported_entities)
            
        self.active_entities = [e for e in self.DEFAULT_ENTITIES if e in supported_entities]

        if self.mode == "accurate":
            spacy_config = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
            }
            nlp_provider = NlpEngineProvider(nlp_configuration=spacy_config)
            nlp_engine = nlp_provider.create_engine()
            self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
        else:
            # Fast mode: No NLP, regex only
            self._analyzer = AnalyzerEngine(registry=registry)

        self._anonymizer = AnonymizerEngine()

        self.operators = {
            "PERSON":        OperatorConfig("custom",  {"lambda": self._mask_name}),
            "PHONE_NUMBER":  OperatorConfig("custom",  {"lambda": self._mask_phone}),
            "EMAIL_ADDRESS": OperatorConfig("custom",  {"lambda": self._mask_email}),
        }
        # For all other entities, replace with <ENTITY_TYPE>
        for entity in self.active_entities:
            if entity not in self.operators:
                self.operators[entity] = OperatorConfig("replace", {"new_value": f"<{entity}>"})

    # ── Masking helpers ────────────────
    def _mask_name(self, text: str) -> str:
        parts = text.split()
        masked = []
        for part in parts:
            if len(part) <= 2:
                masked.append(part)
            else:
                masked.append(part[0] + '*' * (len(part) - 2) + part[-1])
        return ' '.join(masked)

    def _mask_phone(self, text: str) -> str:
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

    def _mask_email(self, text: str) -> str:
        try:
            local, domain = text.split('@', 1)
            d_parts = domain.rsplit('.', 1)
            d_name  = d_parts[0]
            d_ext   = d_parts[1] if len(d_parts) > 1 else ''

            def _partial(s: str) -> str:
                if len(s) <= 1: return s
                if len(s) == 2: return s[0] + '*'
                return s[0] + '*' * (len(s) - 2) + s[-1]

            return f"{_partial(local)}@{_partial(d_name)}.{d_ext}"
        except Exception:
            return '***@***.***'

    # ── Main public method ───────────────────────────────────

    def mask(self, data: Any, custom_rules: List[Any] = None, return_report: bool = False) -> Any:
        if not MASKING_ENABLED:
            if return_report:
                return {"masked_response": data, "entity_types": {}}
            return data

        is_string_json = False
        parsed_data    = data
        if isinstance(data, str):
            try:
                parsed_data    = json.loads(data)
                is_string_json = True
            except (json.JSONDecodeError, ValueError):
                pass 

        report_tracker = {}

        masked_obj = self._recursive_mask(parsed_data, report_tracker=report_tracker)

        if is_string_json:
            masked_text = json.dumps(masked_obj, indent=2)
        elif isinstance(data, str):
            masked_text = masked_obj
        else:
            masked_text = masked_obj

        if custom_rules:
            if not isinstance(masked_text, str):
                masked_text = json.dumps(masked_text, indent=2)
                masked_text = self._apply_custom_rules(masked_text, custom_rules)
                try:
                    masked_text = json.loads(masked_text)
                except Exception:
                    pass
            else:
                masked_text = self._apply_custom_rules(masked_text, custom_rules)

        if return_report:
            return {
                "masked_response": masked_text,
                "entity_types": report_tracker
            }
        
        return masked_text

    def _apply_field_mask(self, value: str, entity_type: str) -> str:
        # Instead of just replacing with <TAG>, run the actual operator on the value
        if entity_type in self.operators:
            operator = self.operators[entity_type]
            if operator.operator_name == "replace":
                return operator.params.get("new_value", f"<{entity_type}>")
            elif operator.operator_name == "custom":
                func = operator.params.get("lambda")
                if func:
                    return func(value)
        return f"<{entity_type}>"

    def _recursive_mask(self, data: Any, report_tracker: dict, current_key: str = None) -> Any:
        if isinstance(data, dict):
            return {k: self._recursive_mask(v, report_tracker, current_key=k) for k, v in data.items()}
        elif isinstance(data, list):
            # Run synchronously to avoid thread-creation overhead for small/medium arrays
            return [self._recursive_mask(i, report_tracker, current_key=current_key) for i in data]
        elif isinstance(data, str):
            # Field-aware masking logic
            if current_key and current_key.lower() in self.field_masks:
                entity_type = self.field_masks[current_key.lower()]
                if entity_type == "AADHAAR" and not validate_aadhaar(data):
                    return data # Do not fall through to NLP masking if field is aadhaar but invalid
                else:
                    report_tracker[entity_type] = report_tracker.get(entity_type, 0) + 1
                    return self._apply_field_mask(data, entity_type)

            # NLP based masking
            results = self._analyzer.analyze(
                text=data, 
                language="en", 
                entities=self.active_entities,
                score_threshold=self.score_threshold
            )
            
            # Filter results
            filtered_results = []
            for res in results:
                # Verhoeff check for Aadhaar
                if res.entity_type == "AADHAAR":
                    extracted = data[res.start:res.end]
                    if not validate_aadhaar(extracted):
                        continue
                
                # Allowlist check
                extracted_lower = data[res.start:res.end].lower()
                if extracted_lower in self.allowlist:
                    continue

                filtered_results.append(res)
                report_tracker[res.entity_type] = report_tracker.get(res.entity_type, 0) + 1
                
            return self._anonymizer.anonymize(
                text=data, analyzer_results=filtered_results, operators=self.operators
            ).text
        return data

    def _apply_custom_rules(self, text: str, rules: List[Any]) -> str:
        for rule in rules:
            pattern      = rule.pattern      if hasattr(rule, 'pattern')      else rule.get('pattern', '')
            position     = rule.position     if hasattr(rule, 'position')     else rule.get('position', 'prefix')
            masking_type = rule.masking_type if hasattr(rule, 'masking_type') else rule.get('masking_type', 'replace')
            replacement  = rule.replacement  if hasattr(rule, 'replacement')  else rule.get('replacement', 'X')

            pat = re.escape(pattern)

            if masking_type == "first_last":
                def _repl(m, _=None):
                    s = m.group(0)
                    return (s[0] + s[-1]) if len(s) > 1 else s
            else:
                _rep = replacement or "X"
                def _repl(m, r=_rep):
                    return r

            try:
                if position == "prefix":
                    text = re.sub(rf'(?<!\S){pat}\S*',   _repl, text, flags=re.IGNORECASE)
                elif position == "suffix":
                    text = re.sub(rf'\S*{pat}(?!\S)',    _repl, text, flags=re.IGNORECASE)
                elif position == "contains":
                    text = re.sub(rf'\S*{pat}\S*',       _repl, text, flags=re.IGNORECASE)
                else:
                    text = re.sub(rf'(?<!\S){pat}(?!\S)', _repl, text, flags=re.IGNORECASE)
            except re.error:
                pass
        return text


# ============================================================
# Shared masker — one instance reused by the decorators/functions
# ============================================================

_shared_masker: SafeGuardMasker = None
_masker_lock = threading.Lock()

def _get_shared_masker() -> SafeGuardMasker:
    """Returns the shared masker, creating it on first use safely."""
    global _shared_masker
    if _shared_masker is None:
        with _masker_lock:
            if _shared_masker is None:
                _shared_masker = SafeGuardMasker(
                    score_threshold=0.7,
                    field_masks={
                        "customer_name": "PERSON",
                        "employee_id": "EMPLOYEE_ID",
                        "aadhaar": "AADHAAR",
                        "pan": "PAN_CARD"
                    },
                    allowlist=["openai", "microsoft", "google"]
                )
    return _shared_masker

def configure(allowlist: List[str] = None, threshold: float = None, mode: str = None, field_masks: Dict[str, str] = None):
    """Configures the shared masker instance. Must be called before first use, or re-initializes it."""
    global _shared_masker
    with _masker_lock:
        if _shared_masker is not None:
            old_allowlist = _shared_masker.allowlist
            old_threshold = _shared_masker.score_threshold
            old_mode = _shared_masker.mode
            old_field_masks = _shared_masker.field_masks
            
            _shared_masker = SafeGuardMasker(
                score_threshold=threshold if threshold is not None else old_threshold,
                field_masks=field_masks if field_masks is not None else old_field_masks,
                allowlist=allowlist if allowlist is not None else old_allowlist,
                mode=mode if mode is not None else old_mode
            )
        else:
            _shared_masker = SafeGuardMasker(
                score_threshold=threshold if threshold is not None else 0.7,
                field_masks=field_masks if field_masks is not None else {
                    "customer_name": "PERSON",
                    "employee_id": "EMPLOYEE_ID",
                    "aadhaar": "AADHAAR",
                    "pan": "PAN_CARD"
                },
                allowlist=allowlist if allowlist is not None else ["openai", "microsoft", "google"],
                mode=mode if mode is not None else "accurate"
            )


# ============================================================
# Public API
# ============================================================

def mask(data: Any, custom_rules: List[Any] = None, return_report: bool = False) -> Any:
    """
    Mask PII in data.
    Accepts: dict, list, JSON string, or plain string.
    Returns: same type as input, with PII replaced.
    """
    return _get_shared_masker().mask(data, custom_rules=custom_rules, return_report=return_report)

def mask_output(func: Callable) -> Callable:
    """
    Decorator: auto-masks the return value of any bot/LLM function.
    """
    if asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)
            if not MASKING_ENABLED:
                return result
            try:
                return _get_shared_masker().mask(result)
            except Exception as e:
                print(f"[SafeGuard] Masking failed, returning original: {e}")
                return result
        return async_wrapper
    else:
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            if not MASKING_ENABLED:
                return result
            try:
                return _get_shared_masker().mask(result)
            except Exception as e:
                print(f"[SafeGuard] Masking failed, returning original: {e}")
                return result
        return sync_wrapper

# ============================================================
# FastAPI / Starlette Middleware
# ============================================================

if STARLETTE_AVAILABLE:
    class SafeGuardMiddleware(BaseHTTPMiddleware):
        """
        FastAPI / Starlette Middleware to automatically mask all outgoing JSON responses.
        
        Usage:
            from fastapi import FastAPI
            from safeguard.masker import SafeGuardMiddleware
            
            app = FastAPI()
            app.add_middleware(SafeGuardMiddleware)
        """
        def __init__(self, app: ASGIApp, masker: Optional[SafeGuardMasker] = None):
            super().__init__(app)
            self.masker = masker or _get_shared_masker()

        async def dispatch(self, request: Request, call_next: Callable) -> Response:
            response = await call_next(request)
            
            if not MASKING_ENABLED:
                return response

            # Skip streaming responses to prevent breaking token streams
            if response.__class__.__name__ == "StreamingResponse":
                return response

            if isinstance(response, JSONResponse) or response.headers.get("content-type") == "application/json":
                # Extract body
                if not hasattr(response, "body_iterator"):
                    return response
                body_iterator = response.body_iterator
                body = b"".join([chunk async for chunk in body_iterator])
                try:
                    data = json.loads(body)
                    masked_data = self.masker.mask(data)
                    return JSONResponse(content=masked_data, status_code=response.status_code)
                except Exception:
                    # If JSON parsing fails, return original
                    return Response(content=body, status_code=response.status_code, headers=dict(response.headers))
            
            return response

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  SafeGuard Masker — Enterprise Demo")
    print("=" * 60)

    bot_response = {
        "customer_name": "May Jordan",
        "aadhaar": "456789012345", # Not mathematically valid, shouldn't mask
        "employee_id": "EMP-4921",
        "details": "Customer May lives in New York and works for OpenAI. Her VIN is 1HGCM82633A00435.",
        "ip_address": "192.168.1.1"
    }

    print("\n[Demo] mask() function with return_report=True")
    print("-" * 50)
    
    report = mask(bot_response, return_report=True)
    print(json.dumps(report, indent=2))