import json
import random
import re
from typing import Any, List

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


class SafeGuardMasker:
    """
    Dynamic Data Masking Engine.
    Uses Microsoft Presidio + spaCy (en_core_web_sm) for NER-based entity tagging.
    """

    PRESIDIO_ENTITIES = ["PERSON", "LOCATION", "ORGANIZATION", "PHONE_NUMBER", "EMAIL_ADDRESS"]

    def __init__(self):
        """
        Initialise the Presidio AnalyzerEngine (with spaCy en_core_web_sm) and
        AnonymizerEngine exactly once; reuse on every subsequent call.
        """
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

        self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
        self._anonymizer = AnonymizerEngine()

        self.operators = {
            "PERSON":        OperatorConfig("custom", {"lambda": self._mask_name}),
            "LOCATION":      OperatorConfig("replace", {"new_value": "<MANUFACTURING_FACILITY>"}),
            "ORGANIZATION":  OperatorConfig("replace", {"new_value": "<VEHICLE_MODEL>"}),
            "PHONE_NUMBER":  OperatorConfig("custom", {"lambda": self._mask_phone}),
            "EMAIL_ADDRESS": OperatorConfig("custom", {"lambda": self._mask_email}),
        }

    def _mask_name(self, text: str) -> str:
        """Show only first and last letter of each word: 'John Carter' → 'J**n C****r'."""
        parts = text.split()
        masked = []
        for part in parts:
            if len(part) <= 2:
                masked.append(part)
            else:
                masked.append(part[0] + '*' * (len(part) - 2) + part[-1])
        return ' '.join(masked)

    def _mask_phone(self, text: str) -> str:
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

    def _mask_email(self, text: str) -> str:
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

    def mask(self, data: Any, custom_rules: List[Any] = None) -> Any:
        """
        Masking entry point.
        Attempts to parse string as JSON for recursive masking; falls back to plain text.
        Applies custom word rules if provided.
        """
        is_string_json = False
        parsed_data = data
        
        # If string, check if it's JSON
        if isinstance(data, str):
            try:
                parsed_data = json.loads(data)
                is_string_json = True
            except (json.JSONDecodeError, ValueError):
                pass
                
        # Apply recursive masking
        masked_obj = self._recursive_mask(parsed_data)
        
        # Format output back to original
        if is_string_json:
            masked_text = json.dumps(masked_obj, indent=2)
        elif isinstance(data, str):
            masked_text = masked_obj
        else:
            masked_text = masked_obj # It's a dict or list natively
            
        # Apply custom rules
        if custom_rules:
            # Custom rules only apply to strings, so we dump to string if it isn't already
            if not isinstance(masked_text, str):
                masked_text = json.dumps(masked_text, indent=2)
                masked_text = self._apply_custom_rules(masked_text, custom_rules)
                try:
                    return json.loads(masked_text)
                except:
                    return masked_text
            else:
                masked_text = self._apply_custom_rules(masked_text, custom_rules)

        return masked_text

    def _recursive_mask(self, data: Any) -> Any:
        """
        Walk any combination of dicts / lists / strings and apply Presidio masking
        to every string value while leaving JSON structural keys untouched.
        """
        if isinstance(data, dict):
            return {
                k: self._recursive_mask(v)
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [
                self._recursive_mask(i)
                for i in data
            ]
        elif isinstance(data, str):
            results = self._analyzer.analyze(text=data, language="en", entities=self.PRESIDIO_ENTITIES)
            return self._anonymizer.anonymize(
                text=data, analyzer_results=results, operators=self.operators
            ).text
        return data

    def _apply_custom_rules(self, text: str, rules: List[Any]) -> str:
        """
        Apply user-defined word masking rules on top of Presidio output.
        Each rule specifies:
          - pattern   : the word/prefix/suffix to match
          - position  : prefix / suffix / contains / exact
          - masking_type:
                "replace"    -> substitute matched token with rule.replacement (e.g. "X")
                "first_last" -> keep only first + last character of matched token
        """
        for rule in rules:
            # Handle rules passed as dicts or objects
            pattern = rule.pattern if hasattr(rule, 'pattern') else rule.get('pattern', '')
            position = rule.position if hasattr(rule, 'position') else rule.get('position', 'prefix')
            masking_type = rule.masking_type if hasattr(rule, 'masking_type') else rule.get('masking_type', 'replace')
            replacement = rule.replacement if hasattr(rule, 'replacement') else rule.get('replacement', 'X')

            pat = re.escape(pattern)

            # Build the masking callable
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
                    text = re.sub(rf'(?<!\S){pat}\S*', _repl, text, flags=re.IGNORECASE)
                elif position == "suffix":
                    text = re.sub(rf'\S*{pat}(?!\S)', _repl, text, flags=re.IGNORECASE)
                elif position == "contains":
                    text = re.sub(rf'\S*{pat}\S*', _repl, text, flags=re.IGNORECASE)
                else:  # exact
                    text = re.sub(rf'(?<!\S){pat}(?!\S)', _repl, text, flags=re.IGNORECASE)
            except re.error:
                pass  # skip malformed patterns gracefully
        return text
