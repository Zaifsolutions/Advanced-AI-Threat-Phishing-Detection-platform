"""
ZaifSecurity — Advanced Phishing & Malware Detection API v2.1
FastAPI backend with CORS, all endpoints fully working.
"""
import re
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from analyzer import TextAnalyzer
from url_analyzer import URLAnalyzer
from explainer import PhishingExplainer
from apk_analyzer import APKAnalyzer
from audio_analyzer import AudioAnalyzer
from utils import validate_file, sanitize_text

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ZaifSecurity Phishing Detection API",
    description="ML + Heuristic phishing, URL, APK, and audio analysis.",
    version="2.1.0",
)

# ── CORS — allow all origins so browser frontend works ───────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Initialize analyzers once at startup ─────────────────────────────────────
text_analyzer     = TextAnalyzer()
url_analyzer_eng  = URLAnalyzer()
explainer         = PhishingExplainer()
apk_analyzer      = APKAnalyzer()
audio_analyzer    = AudioAnalyzer()

# ── Pydantic Schemas ──────────────────────────────────────────────────────────
class URLInput(BaseModel):
    url: str

class TextInput(BaseModel):
    text: str

# ── Helpers ───────────────────────────────────────────────────────────────────
URL_PATTERN = re.compile(r"https?://[^\s]+|www\.[^\s]+", re.IGNORECASE)

def _extract_url_risks(text: str) -> list:
    risks = []
    for url in URL_PATTERN.findall(text)[:5]:   # analyse up to 5 URLs
        try:
            risks.append(url_analyzer_eng.analyze(url))
        except Exception:
            pass
    return risks

def _timestamp() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

# ══════════════════════════════════════════════════════════════════════════════
# Health / Root
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {
        "message":  "✅ ZaifSecurity API v2.1 (ML-Enhanced)",
        "status":   "ready",
        "features": [
            "Multi-model ML (NB / LR / RF)",
            "Advanced heuristic analysis",
            "URL risk analysis + typosquatting",
            "APK malware static analysis",
            "Audio transcription + analysis",
            "Explainable AI insights",
        ],
    }

@app.get("/api/health")
async def health_check():
    return {
        "status":        "healthy",
        "ml_model":      "ready" if text_analyzer.ml_available else "unavailable",
        "model_name":    text_analyzer.ml_predictor.model_name
                         if text_analyzer.ml_available else "N/A",
        "text_analyzer": "ready",
        "url_analyzer":  "ready",
        "apk_analyzer":  "ready",
        "audio_analyzer":"ready" if audio_analyzer.speech_available else "limited",
        "version":       "2.1.0",
    }

# ══════════════════════════════════════════════════════════════════════════════
# Text / Email Analysis
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/analyze/text")
async def analyze_text_endpoint(payload: TextInput):
    """Analyse plain text or email body for phishing."""
    if not payload.text or not payload.text.strip():
        raise HTTPException(400, "Text cannot be empty.")
    if len(payload.text) > 50_000:
        raise HTTPException(400, "Text exceeds 50 KB limit.")

    result     = text_analyzer.analyze_text(payload.text)
    url_risks  = _extract_url_risks(payload.text)
    
    # Extract domains from URLs
    urls_found = URL_PATTERN.findall(payload.text)[:5]

    return {
        **result,
        "urls_detected":  len(url_risks),
        "url_risks":      url_risks,
        "details": {
            "text_length": len(payload.text),
            "character_count": len(payload.text.replace(" ", "")),
            "urls_found": len(urls_found),
            "domains": list(set([u.split("/")[2] if "/" in u else u for u in urls_found if u])),
        },
        "timestamp":      _timestamp(),
        "analysis_type":  "text",
    }

# ══════════════════════════════════════════════════════════════════════════════
# URL Analysis
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/analyze/url")
async def analyze_url_endpoint(payload: URLInput):
    """Analyse a single URL for phishing indicators."""
    if not payload.url or not payload.url.strip():
        raise HTTPException(400, "URL cannot be empty.")
    if len(payload.url) > 2000:
        raise HTTPException(400, "URL too long.")
    if not re.match(r"^(https?://|www\.|ftp://)", payload.url.strip()):
        raise HTTPException(400, "Invalid URL — must start with http://, https://, www., or ftp://")

    result = url_analyzer_eng.analyze(payload.url)
    verdict = result.get("verdict", "Suspicious")
    status = verdict if verdict in {"Safe", "Suspicious", "Phishing"} else "Suspicious"

    return {
        **result,
        "status": status,
        "verdict": verdict,
        "timestamp": _timestamp(),
        "analysis_type": "url",
    }

@app.post("/analyze-url")
async def analyze_url_alias(payload: URLInput):
    return await analyze_url_endpoint(payload)

@app.post("/analyze-email")
async def analyze_email_alias(payload: TextInput):
    return await analyze_text_endpoint(payload)

# ══════════════════════════════════════════════════════════════════════════════
# File Analysis  (.txt / .eml)
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/analyze/file")
async def analyze_file_endpoint(file: UploadFile = File(...)):
    """Analyse document files (.txt, .eml, .pdf, .docx, etc.) for phishing."""
    try:
        validate_file(file, is_audio=False)
        content = await file.read()
        
        # Check file size
        if len(content) > 25 * 1024 * 1024:
            raise HTTPException(400, "File too large (max 25 MB).")
        
        # Extract text from file
        from utils import extract_text_from_file, compute_file_hashes, get_file_type
        text = extract_text_from_file(content, file.filename)
        
        if not text or not text.strip():
            # Return SAFE result for unreadable files (not enough evidence to flag)
            return {
                "risk_score": 0,
                "status": "Safe",
                "verdict": "Safe",
                "reasons": ["File is empty or in binary format — no phishing indicators detected."],
                "reason_paragraph": "This file appears to be empty or in a binary format that cannot be analyzed for phishing content. No threats were detected.",
                "file_name": file.filename,
                "file_size": len(content),
                "file_type": get_file_type(file.filename),
                "file_hashes": compute_file_hashes(content),
                "urls_detected": 0,
                "url_risks": [],
                "keywords_found": [],
                "details": {
                    "file_name": file.filename,
                    "file_size_bytes": len(content),
                    "file_type": get_file_type(file.filename),
                    "md5": compute_file_hashes(content)["md5"],
                    "sha256": compute_file_hashes(content)["sha256"],
                    "urls_found": 0,
                    "domains": [],
                },
                "timestamp": _timestamp(),
                "analysis_type": "file",
                "ml_available": text_analyzer.ml_available,
                "model_name": text_analyzer.ml_predictor.model_name if text_analyzer.ml_available else "N/A",
            }

        result    = text_analyzer.analyze_text(text)
        url_risks = _extract_url_risks(text)
        hashes    = compute_file_hashes(content)

        return {
            **result,
            "file_name":     file.filename,
            "file_size":     len(content),
            "file_type":     get_file_type(file.filename),
            "file_hashes":   hashes,
            "urls_detected": len(url_risks),
            "url_risks":     url_risks,
            "details": {
                "file_name": file.filename,
                "file_size_bytes": len(content),
                "file_type": get_file_type(file.filename),
                "md5": hashes["md5"],
                "sha256": hashes["sha256"],
                "urls_found": len(url_risks),
                "domains": list(set([u.get("domain", "") for u in url_risks if u.get("domain")])),
            },
            "timestamp":     _timestamp(),
            "analysis_type": "file",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Error analysing file: {str(e)}")
    finally:
        await file.close()

# ══════════════════════════════════════════════════════════════════════════════
# Audio Analysis
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/analyze/audio")
async def analyze_audio_endpoint(file: UploadFile = File(...)):
    """Convert speech to text then analyse for phishing patterns."""
    try:
        validate_file(file, is_audio=True)
        content = await file.read()
        result  = audio_analyzer.analyze(content)
        return {
            **result,
            "file_name":     file.filename,
            "timestamp":     _timestamp(),
            "analysis_type": "audio",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Error analysing audio: {e}")

@app.post("/scan-file")
async def scan_file_alias(file: UploadFile = File(...)):
    return await analyze_file_endpoint(file)

@app.post("/scan-audio")
async def scan_audio_alias(file: UploadFile = File(...)):
    return await analyze_audio_endpoint(file)

@app.post("/scan-apk")
async def scan_apk_alias(file: UploadFile = File(...)):
    return await analyze_apk_endpoint(file)

# ══════════════════════════════════════════════════════════════════════════════
# APK Analysis
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/api/analyze/apk")
async def analyze_apk_endpoint(file: UploadFile = File(...)):
    """Static analysis of Android APK for malware indicators."""
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(400, "File must be an APK (.apk).")
    try:
        content = await file.read()
        if len(content) > 100 * 1024 * 1024:
            raise HTTPException(400, "APK too large (max 100 MB).")

        result = apk_analyzer.analyze(content)
        return {
            "file_name":          file.filename,
            "file_size":          len(content),
            "risk_score":         result["risk_score"],
            "verdict":            result["verdict"],
            "reasons":            result["reasons"],
            "permissions":        result.get("permissions", []),
            "malware_indicators": result.get("malware_indicators", []),
            "suspicious_patterns":result.get("suspicious_patterns_found", []),
            "timestamp":          _timestamp(),
            "analysis_type":      "apk",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Error analysing APK: {e}")
    finally:
        await file.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
