# SafeGuard PII Masker

Welcome to **SafeGuard**! This is a plug-and-play Python library that automatically detects and hides sensitive user information (like Names, Emails, Phone Numbers, Aadhaar, PAN, and Credit Cards) before it ever leaves your app.

If you are building a Chatbot, an API, or working with a database, you can use this to instantly ensure no sensitive data leaks out.

---

## 🚀 How to use this in your code (in under 2 minutes)

### Step 1: Install the Package
Open your terminal and run this command. It will automatically install the library and download the background AI models for you:

*(If you were given a link to the Git repository, run this)*:
```bash
pip install git+https://github.com/YourCompany/MaskingApiNew.git
```
*(If you have downloaded this folder to your computer, navigate inside the folder and run this)*:
```bash
pip install -e .
```

---

### Step 2: Import it into your Python file
Open the Python file where your application is running (for example, the file where your chatbot generates its response, or your API sends data back). 

At the very top of that file, add this single line:
```python
from safeguard import mask
```

---

### Step 3: Mask your data!
Find the exact spot in your code where you have the data you want to protect. It doesn't matter if it's a string of text, a list, or a massive nested JSON dictionary. Just wrap it in the `mask()` function.

**Before:**
```python
# Your existing code might look something like this:
return chatbot_response
```

**After:**
```python
# Just wrap it in mask()!
safe_response = mask(chatbot_response)

return safe_response
```

That's it! Your code will now automatically detect and replace all sensitive data with safe placeholder tags (like `<PERSON>` or `<CREDIT_CARD>`).

---

## 🛠️ Advanced Usage (Optional)

### Option 2: Automatic Decorator
If you don't want to wrap variables manually, you can just add `@mask_output` above the function that returns your data. The masking will happen automatically before the data is returned!

```python
from safeguard import mask_output

@mask_output
def get_bot_reply(prompt):
    return call_your_llm(prompt) # Returns raw text, automatically masked!
```

### Option 3: FastAPI Middleware (Zero-Code Change)
If you are running a FastAPI server, you can mask all outgoing JSON responses across your entire server with just two lines:

```python
from fastapi import FastAPI
from safeguard import SafeGuardMiddleware

app = FastAPI()

# Add this line. Every JSON response will now be automatically masked!
app.add_middleware(SafeGuardMiddleware)
```
*(Note: SafeGuard safely ignores Token Streaming responses to avoid breaking your LLM stream.)*

### Custom Settings
If you want to skip masking for specific company names (like "OpenAI"), or use a faster mode, you can configure it at the very start of your app:

```python
from safeguard import configure

configure(
    allowlist=["OpenAI", "Microsoft"], 
    mode="fast"  # Bypasses the heavy NLP model for massive speedups
)
```

Enjoy building securely!
