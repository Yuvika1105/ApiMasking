# SafeGuard PII Masker

A drop-in Python script that automatically detects and masks Personally Identifiable Information (PII) like Names, Emails, Phone Numbers, and Locations in your chatbot or API responses.

## Quick Start

### 1. Install Dependencies
Run these two commands in your terminal once:
```bash
pip install presidio-analyzer presidio-anonymizer spacy
python -m spacy download en_core_web_lg
```

### 2. Copy the File
Just copy `safeguard/masker.py` directly into your own project folder.

### 3. Use It! (Two Options)

#### Option A: Automatic Decorator (Recommended)
Add `@mask_output` above the function that returns your bot's response. The masking will happen automatically before the data is returned!

```python
from safeguard.masker import mask_output

@mask_output
def get_bot_reply(prompt):
    return call_your_llm(prompt) # Returns raw PII

# Caller receives masked data!
reply = get_bot_reply("Who is the engineer?") 
# Example output: "Engineer J**n D*e (XXXXXXX210) will visit <MANUFACTURING_FACILITY>"
```

#### Option B: Manual Call
If you already have a dictionary, list, or string and just want to mask it:

```python
from safeguard.masker import SafeGuardMasker

masker = SafeGuardMasker() # Creates model once in memory
safe_response = masker.mask(your_bot_response)
```

## Features
- **Works with any format:** Accepts plain text, deeply nested JSON dicts, lists, and SQL query rows.
- **Context-Free Detection:** Upgraded to the `en_core_web_lg` AI model so it detects isolated locations and names inside SQL table rows and grids without needing surrounding sentences.
- **Smart Formatting:** Leaves booleans, numbers, and JSON keys completely untouched. Only sensitive string values are changed.
- **Developer Toggle:** Change `MASKING_ENABLED = False` inside the file during local development to disable masking temporarily.
