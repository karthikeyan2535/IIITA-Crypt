from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List
from config import get_settings
import base64
import binascii
import hmac
import hashlib
import os
import re

# Agent Beta: MSK Persistence Logic
MSK_FILE = os.path.join(os.path.dirname(__file__), "master.key")

def get_msk(settings) -> str:
    if os.path.exists(MSK_FILE):
        with open(MSK_FILE, "r") as f:
            return f.read().strip()
    else:
        # Fallback to .env if file doesn't exist, then persist it
        msk = settings.msk
        with open(MSK_FILE, "w") as f:
            f.write(msk)
        return msk

# Case 3.2: Sanitize error messages before exposing them
def _sanitize_err(msg: str) -> str:
    """Strip ciphertext fragments, hex digests, and stack traces from error strings."""
    msg = str(msg)
    msg = re.sub(r'[A-Za-z0-9+/]{40,}={0,2}', '[BASE64_REDACTED]', msg)
    msg = re.sub(r'[0-9a-fA-F]{32,}', '[HEX_REDACTED]', msg)
    return msg[:200]

app = FastAPI(title="IIITA-Crypt - Encryption Service")

class EncryptRequest(BaseModel):
    plaintext: str
    policy: str

class DecryptRequest(BaseModel):
    ciphertext: str
    attributes: List[str]

class BatchDecryptRequest(BaseModel):
    ciphertext: str
    attributes: List[str]
    policy: str

@app.get("/health")
def health_check():
    return {"status": "OK", "service": "encryption"}

@app.post("/encrypt")
def encrypt(request: EncryptRequest, settings=Depends(get_settings)):
    # Force Policy to UPPERCASE
    policy = request.policy.strip().upper()
    raw_payload = f"CP-ABE[Policy:{policy}]|Data:{request.plaintext}"
    encoded_cipher = base64.b64encode(raw_payload.encode('utf-8')).decode('utf-8')
    
    # Sign with Persisted MSK
    msk = get_msk(settings)
    signature = hmac.new(msk.encode(), encoded_cipher.encode(), hashlib.sha256).hexdigest()
    final_ciphertext = f"{signature}.{encoded_cipher}"
    
    return {"ciphertext": final_ciphertext}

@app.post("/decrypt")
def decrypt(request: DecryptRequest, settings=Depends(get_settings)):
    return _evaluate_policy(request.ciphertext, request.attributes, "", settings)

@app.post("/decrypt-batch")
def decrypt_batch(request: BatchDecryptRequest, settings=Depends(get_settings)):
    return _evaluate_policy(request.ciphertext, request.attributes, request.policy, settings)

def _evaluate_policy(ciphertext: str, attributes: List[str], policy: str, settings) -> dict:
    # 1. Attribute Normalization (Rule: Force UPPERCASE and strip)
    norm_attrs = [a.strip().upper() for a in attributes]
    print(f"[Beta Received] normalized_attributes={norm_attrs}")
    
    # 2. Structural validation: must contain exactly one '.' separator
    if "." not in ciphertext:
        raise HTTPException(status_code=422, detail="[REDACTED: Invalid ciphertext structure — missing HMAC separator]")
    
    signature, encoded_cipher = ciphertext.split(".", 1)

    # 3. Case 3.2: Safely decode base64 — catch padding/encoding corruption
    try:
        # Add padding if needed (Atlas can strip trailing '=')
        padded = encoded_cipher + '=' * (-len(encoded_cipher) % 4)
        raw_decoded = base64.b64decode(padded)
    except (binascii.Error, ValueError):
        print("[Beta] base64 decode failed — ciphertext is corrupted")
        raise HTTPException(status_code=422, detail="[REDACTED: Corrupted ciphertext — base64 decode failed]")

    # 4. Verify MSK HMAC Signature
    msk = get_msk(settings)
    expected_sig = hmac.new(msk.encode(), encoded_cipher.encode(), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(signature, expected_sig):
        raise HTTPException(status_code=403, detail="[REDACTED: Ciphertext Tampering Detected — HMAC mismatch]")

    # 5. Dean/Admin Override
    if "DEAN" in norm_attrs or "ADMIN" in norm_attrs:
        try:
            decoded = raw_decoded.decode('utf-8')
            if "|Data:" in decoded:
                plaintext = decoded.split("|Data:")[1]
                return {"plaintext": plaintext}
        except (UnicodeDecodeError, IndexError):
            pass
        return {"plaintext": "[DEAN OVERRIDE] Access granted."}

    # 6. Decrypt and Evaluate Policy
    try:
        decoded = raw_decoded.decode('utf-8')
    except UnicodeDecodeError:
        # Case 3.2: Corrupted plaintext content (not valid UTF-8)
        print("[Beta] UTF-8 decode failed — plaintext portion corrupted")
        raise HTTPException(status_code=422, detail="[REDACTED: Document content corrupted — UTF-8 decode failed]")

    try:
        embedded_policy = ""
        plaintext_data = decoded

        if "CP-ABE[Policy:" in decoded and "|Data:" in decoded:
            embedded_policy = decoded.split("CP-ABE[Policy:")[1].split("]")[0]
            plaintext_data = decoded.split("|Data:")[1]

        effective_policy = (embedded_policy or policy).strip().upper()
        print(f"[Beta] Effective policy: '{effective_policy}'")

        if effective_policy == "PUBLIC" or not effective_policy:
            return {"plaintext": plaintext_data}

        # Agent Beta: Fail-closed policy evaluation
        # Each clause is evaluated defensively. Any exception in a clause
        # is treated as False (not satisfied), never as a structural error leak.
        def check_clause(clause: str) -> bool:
            try:
                # Aggressive normalization — double-pass to catch any encoding edge cases
                parts = [p.strip().upper().strip() for p in clause.split(" AND ")]
                parts = [p for p in parts if p]  # drop empty strings from malformed input
                if not parts:
                    return False
                return all(p in norm_attrs for p in parts)
            except Exception:
                # Fail-closed: unrecognizable clause structure → treat as unsatisfied
                return False

        try:
            if " OR " in effective_policy:
                or_clauses = [c.strip() for c in effective_policy.split(" OR ")]
                satisfied = any(check_clause(c) for c in or_clauses if c)
            else:
                satisfied = check_clause(effective_policy)
        except Exception:
            # Outer fail-closed: any unhandled evaluation error → hard deny
            satisfied = False

        if satisfied:
            return {"plaintext": plaintext_data}
        else:
            raise HTTPException(
                status_code=403,
                detail=f"[REDACTED: Access Denied] Policy not satisfied."
            )

    except HTTPException:
        raise
    except (KeyError, IndexError, AttributeError) as parse_err:
        # Case 3.2: Malformed policy string or corrupted embedded structure
        safe = _sanitize_err(str(parse_err))
        print(f"[Beta] Policy parse error: {safe}")
        raise HTTPException(status_code=422, detail="[REDACTED: Malformed policy structure in ciphertext]")
    except Exception as e:
        # Last-resort catch — sanitize before logging or returning
        safe = _sanitize_err(str(e))
        print(f"[Beta] Unexpected decryption error: {safe}")
        raise HTTPException(status_code=403, detail="[REDACTED: Decryption failed]")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
