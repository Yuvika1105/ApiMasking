
# ============================================================
# masker.py — Auto PII Masking for Any Chatbot or API
# ============================================================
#
# This file hides sensitive info (names, emails, phone numbers,
# locations) inside your bot's JSON responses before they reach
# the user. It uses Microsoft Presidio + spaCy to detect PII.
#
# ── QUICK SETUP (run once in your terminal) ─────────────────
#
#   pip install presidio-analyzer presidio-anonymizer spacy
#   python -m spacy download en_core_web_lg
#
# ── HOW TO USE IN YOUR PROJECT ──────────────────────────────
#
#   OPTION A — Decorator (easiest, recommended for real-time bots)
#   Just add @mask_output above your bot response function:
#
#       from safeguard.masker import mask_output
#
#       @mask_output                    ← add this one line
#       def get_bot_reply(prompt):
#           return call_your_llm(prompt)   # your code unchanged
#
#       reply = get_bot_reply("Who is the engineer?")
#       # reply is already masked — names, emails, phones hidden
#
#   OPTION B — Manual call (when you already have the response)
#
#       from safeguard.masker import SafeGuardMasker
#
#       masker   = SafeGuardMasker()            # create once
#       raw      = your_bot.get_response(...)   # whatever your bot returns
#       safe     = masker.mask(raw)             # mask it
#       send_to_user(safe)                      # send the safe version
#
#   OPTION C — FastAPI middleware (masks all JSON responses automatically)
#
#       from fastapi import FastAPI, Request
#       from fastapi.responses import JSONResponse
#       from safeguard.masker import SafeGuardMasker
#       import json
#
#       app    = FastAPI()
#       masker = SafeGuardMasker()
#
#       @app.middleware("http")
#       async def auto_mask(request: Request, call_next):
#           response = await call_next(request)
#           if "application/json" in response.headers.get("content-type", ""):
#               body = b""
#               async for chunk in response.body_iterator:
#                   body += chunk
#               masked = masker.mask(json.loads(body))
#               return JSONResponse(content=masked, status_code=response.status_code)
#           return response
#
#   OPTION D — Flask (masks all JSON responses automatically)
#
#       from flask import Flask
#       from safeguard.masker import SafeGuardMasker
#       import json
#
#       app    = Flask(__name__)
#       masker = SafeGuardMasker()
#
#       @app.after_request
#       def auto_mask(response):
#           if "application/json" in response.content_type:
#               masked = masker.mask(response.get_json(silent=True) or {})
#               response.set_data(json.dumps(masked))
#           return response
#
# ── TURN MASKING ON / OFF ────────────────────────────────────
#
#   Change MASKING_ENABLED below (or flip it from your code):
#
#       import safeguard.masker as m
#       m.MASKING_ENABLED = False   # OFF — useful during development
#       m.MASKING_ENABLED = True    # ON  — use in production
#
# ── WHAT GETS MASKED ────────────────────────────────────────
#
#   Names        John Carter   →  J**n C****r
#   Phones       9876543210    →  XXXXXXX210
#   Emails       john@ex.com   →  j**n@e*.com
#   Locations    Halol Plant   →  <MANUFACTURING_FACILITY>
#   Orgs         ACME Corp     →  <VEHICLE_MODEL>
#
#   Numbers, booleans, and JSON keys are NEVER touched.
#
# ── CUSTOM RULES (optional) ──────────────────────────────────
#
#   For tokens Presidio won't catch (e.g. VINs, employee IDs):
#
#       rules = [
#           {"pattern": "VIN", "position": "prefix",
#            "masking_type": "replace", "replacement": "[VIN-HIDDEN]"},
#       ]
#       safe = masker.mask(response, custom_rules=rules)
#
# ── VERIFY SETUP ─────────────────────────────────────────────
#
#   python safeguard/masker.py
#
#   Prints a before/after demo so you can see masking in action.
#
# ============================================================

import asyncio
import functools
import json
import os
import re
from typing import Any, Callable, List

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# ── Middleware toggle ────────────────────────────────────────
# True  = masking is ON  (default — use in production)
# False = masking is OFF (useful while developing/debugging)
# Can also be set via environment variable: SAFEGUARD_ENABLED=false
MASKING_ENABLED: bool = os.environ.get("SAFEGUARD_ENABLED", "true").lower() != "false"


# ============================================================
# SafeGuardMasker — the core masking class
# ============================================================
# You create one instance of this at startup and reuse it.
# It loads the NLP model once and keeps it in memory.

class SafeGuardMasker:
    """
    Masks PII in any string, dict, or list using Microsoft Presidio + spaCy.
    Create once, call .mask() as many times as needed.
    """

    # These are the entity types that will be detected and masked.
    # Add or remove types here if you need to handle more/fewer.
    PRESIDIO_ENTITIES = ["PERSON", "LOCATION", "ORGANIZATION", "PHONE_NUMBER", "EMAIL_ADDRESS"]

    def __init__(self):
        # Download the spaCy English model automatically if it's not installed.
        try:
            import spacy
            import spacy.util
            if not spacy.util.is_package("en_core_web_lg"):
                spacy.cli.download("en_core_web_lg")
        except Exception as e:
            print(f"[SafeGuard] Could not auto-download spaCy model: {e}")
            print("[SafeGuard] Run manually: python -m spacy download en_core_web_lg")

        # Set up Presidio — the NLP engine that finds PII.
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()

        spacy_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
        }
        nlp_provider = NlpEngineProvider(nlp_configuration=spacy_config)
        nlp_engine = nlp_provider.create_engine()

        self._analyzer   = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
        self._anonymizer = AnonymizerEngine()

        # How each entity type gets masked.
        # Change the "new_value" strings here to use different replacement tags.
        self.operators = {
            "PERSON":        OperatorConfig("custom",  {"lambda": self._mask_name}),
            "LOCATION":      OperatorConfig("replace", {"new_value": "<MANUFACTURING_FACILITY>"}),
            "ORGANIZATION":  OperatorConfig("replace", {"new_value": "<VEHICLE_MODEL>"}),
            "PHONE_NUMBER":  OperatorConfig("custom",  {"lambda": self._mask_phone}),
            "EMAIL_ADDRESS": OperatorConfig("custom",  {"lambda": self._mask_email}),
        }

    # ── Masking helpers (one per entity type) ────────────────

    def _mask_name(self, text: str) -> str:
        # Keeps first and last letter of each word: John Carter → J**n C****r
        parts = text.split()
        masked = []
        for part in parts:
            if len(part) <= 2:
                masked.append(part)
            else:
                masked.append(part[0] + '*' * (len(part) - 2) + part[-1])
        return ' '.join(masked)

    def _mask_phone(self, text: str) -> str:
        # Shows only the last 3 digits: 9876543210 → XXXXXXX210
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
        # Hides most of the email: john@gmail.com → j**n@g**l.com
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

    def mask(self, data: Any, custom_rules: List[Any] = None) -> Any:
        """
        Mask PII in data. Call this wherever your bot returns a response.

        Accepts: dict, list, JSON string, or plain string.
        Returns: same type as input, with PII replaced.

        If MASKING_ENABLED is False, returns data unchanged (no-op).
        """
        # If masking is turned OFF globally, return data as-is.
        if not MASKING_ENABLED:
            return data

        # If the input is a JSON string, parse it so we can walk its values.
        is_string_json = False
        parsed_data    = data
        if isinstance(data, str):
            try:
                parsed_data    = json.loads(data)
                is_string_json = True
            except (json.JSONDecodeError, ValueError):
                pass  # not JSON — treat as plain text

        # Recursively mask every string value in the data.
        masked_obj = self._recursive_mask(parsed_data)

        # Return in the same format the caller passed in.
        if is_string_json:
            masked_text = json.dumps(masked_obj, indent=2)
        elif isinstance(data, str):
            masked_text = masked_obj
        else:
            masked_text = masked_obj  # dict or list — keep as-is

        # Apply any extra custom word rules on top of Presidio's output.
        if custom_rules:
            if not isinstance(masked_text, str):
                masked_text = json.dumps(masked_text, indent=2)
                masked_text = self._apply_custom_rules(masked_text, custom_rules)
                try:
                    return json.loads(masked_text)
                except Exception:
                    return masked_text
            else:
                masked_text = self._apply_custom_rules(masked_text, custom_rules)

        return masked_text

    def _recursive_mask(self, data: Any) -> Any:
        # Walk dicts, lists, and strings — mask every string value.
        # Keys, numbers, booleans are never changed.
        if isinstance(data, dict):
            return {k: self._recursive_mask(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._recursive_mask(i) for i in data]
        elif isinstance(data, str):
            results = self._analyzer.analyze(text=data, language="en", entities=self.PRESIDIO_ENTITIES)
            return self._anonymizer.anonymize(
                text=data, analyzer_results=results, operators=self.operators
            ).text
        return data  # numbers, booleans, None — unchanged

    def _apply_custom_rules(self, text: str, rules: List[Any]) -> str:
        # Apply user-defined word rules (e.g. VIN numbers, employee IDs).
        # Each rule is a dict with: pattern, position, masking_type, replacement.
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
                else:  # exact match
                    text = re.sub(rf'(?<!\S){pat}(?!\S)', _repl, text, flags=re.IGNORECASE)
            except re.error:
                pass  # skip bad patterns silently
        return text


# ============================================================
# Shared masker — one instance reused by the @mask_output decorator.
# You can also import this directly:
#   from safeguard.masker import _get_shared_masker
#   safe = _get_shared_masker().mask(bot_response)
# ============================================================

_shared_masker: SafeGuardMasker = None

def _get_shared_masker() -> SafeGuardMasker:
    """Returns the shared masker, creating it on first use."""
    global _shared_masker
    if _shared_masker is None:
        _shared_masker = SafeGuardMasker()
    return _shared_masker


# ============================================================
# @mask_output — decorator for real-time automatic masking
# ============================================================
# Add this above any function that returns a bot / LLM response.
# The function itself stays completely unchanged.
# Every time it returns, the output is automatically masked.
#
# Works with both regular and async functions.
#
# Example:
#   @mask_output
#   def get_reply(prompt):
#       return call_llm(prompt)   # returns raw PII
#
#   reply = get_reply("Who is the engineer?")
#   # reply is already masked — caller never sees raw PII
# ============================================================

def mask_output(func: Callable) -> Callable:
    """
    Decorator: auto-masks the return value of any bot/LLM function.
    Respects MASKING_ENABLED — set it to False to bypass masking.
    """
    if asyncio.iscoroutinefunction(func):
        # Handle async functions (e.g. FastAPI route handlers)
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)  # run the original function
            if not MASKING_ENABLED:
                return result                     # skip masking if toggle is OFF
            try:
                return _get_shared_masker().mask(result)  # mask and return
            except Exception as e:
                print(f"[SafeGuard] Masking failed, returning original: {e}")
                return result
        return async_wrapper
    else:
        # Handle regular (sync) functions
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            result = func(*args, **kwargs)        # run the original function
            if not MASKING_ENABLED:
                return result                     # skip masking if toggle is OFF
            try:
                return _get_shared_masker().mask(result)  # mask and return
            except Exception as e:
                print(f"[SafeGuard] Masking failed, returning original: {e}")
                return result
        return sync_wrapper


# ============================================================
# Run this file directly to see a live demo:
#   python safeguard/masker.py
# ============================================================

if __name__ == "__main__":

    print("\n" + "=" * 60)
    print("  SafeGuard Masker — Live Demo")
    print("=" * 60)

    # ── Demo 1: @mask_output decorator ──────────────────────
    # This is the recommended way for real-time bots.
    # Just add @mask_output above your bot response function.
    # The function body never changes.

    @mask_output  # ← this one line is all you add in your project
    def simulate_bot_response(user_prompt: str) -> dict:
        # In your real project, this would call your actual LLM:
        #   return openai_client.chat.completions.create(...)
        #   return gemini_model.generate_content(user_prompt).text
        #   return your_rag_pipeline.query(user_prompt)
        #
        # Here we return fake data to show the demo:
        return {
            "answer": (
                f"Re: '{user_prompt}' — "
                "Technician John Carter (john.carter@acme.com, "
                "+91-9876543210) will visit Halol Plant for ACME Corp."
            ),
            "ticket_id":  4821,   # number  — will NOT be masked
            "confidence": 0.97,   # float   — will NOT be masked
            "escalated":  False,  # boolean — will NOT be masked
            "metadata": {
                "raised_by": "Alice Sharma",      # name  — WILL be masked
                "contact":   "alice@example.com", # email — WILL be masked
            },
        }

    # Call the bot just like you normally would.
    # Masking happens automatically before the result comes back.
    USER_PROMPT = "What is the status of the technician visit?"

    print("\n[Demo 1]  @mask_output — automatic real-time masking")
    print("-" * 50)
    result = simulate_bot_response(USER_PROMPT)
    print(f"User asked : {USER_PROMPT}")
    print(f"\nBot replied (already masked):")
    print(json.dumps(result, indent=2))

    # ── Demo 2: masker.mask() manual call ───────────────────
    # Use this when you already have the bot's response
    # as a variable and want to mask it before sending it on.

    print("\n\n[Demo 2]  masker.mask() — manual call")
    print("-" * 50)

    # ↓ Replace this with your actual bot/LLM response
    YOUR_BOT_RESPONSE = {
        "answer": "Engineer David Lee (david@corp.com, 9000012345) filed a report at Sanand Plant.",
        "ref_id": 99,   # number — will NOT be masked
    }
    # ↑ e.g. response.choices[0].message.content  or  response.text

    masker = SafeGuardMasker()        # create once at app startup
    MASKED_RESPONSE = masker.mask(YOUR_BOT_RESPONSE)   # ← masking call

    print("Raw   :", json.dumps(YOUR_BOT_RESPONSE))
    print("Masked:", json.dumps(MASKED_RESPONSE))

    # ── Demo 3: middleware toggle ────────────────────────────
    # Set MASKING_ENABLED = False to disable masking globally.
    # Useful when debugging locally and you need to see raw output.

    print("\n\n[Demo 3]  MASKING_ENABLED = False (pass-through mode)")
    print("-" * 50)

    MASKING_ENABLED = False   # masking is now OFF

    raw_result = simulate_bot_response(USER_PROMPT)
    print("Output (masking OFF — raw, no PII hidden):")
    print(json.dumps(raw_result, indent=2))

    MASKING_ENABLED = True    # turn masking back ON
    print("\nMASKING_ENABLED reset to True — masking is active again.")

    print("\n" + "=" * 60)
    print("  In your project, choose either:")
    print("    @mask_output   above your bot function  (automatic)")
    print("    masker.mask()  wherever you return data (manual)")
    print("=" * 60 + "\n")