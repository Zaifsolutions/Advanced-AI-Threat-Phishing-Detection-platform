# 🔌 BACKEND API DOCUMENTATION

## Advanced Phishing Detection Platform v2.1.0

---

## 📋 Quick Reference

| Endpoint | Method | Purpose | Rate Limit |
|----------|--------|---------|-----------|
| `/api/health` | GET | Health check | Unlimited |
| `/api/analyze/text` | POST | Analyze email/text | 100/min |
| `/api/analyze/url` | POST | Analyze URL | 100/min |
| `/api/analyze/file` | POST | Analyze uploaded file | 50/min |
| `/api/analyze/apk` | POST | Analyze Android APK | 50/min |
| `/api/analyze/audio` | POST | Analyze audio file | 50/min |
| `/api/batch/analyze` | POST | Batch analysis | 20/min |

---

## 🏥 Health Check

### Endpoint
```
GET /api/health
```

### Response (200 OK)
```json
{
  "status": "healthy",
  "version": "2.1.0",
  "timestamp": "2026-05-20T14:30:45.123456Z",
  "components": {
    "text_analyzer": "operational",
    "url_analyzer": "operational",
    "ml_predictor": "loaded",
    "file_processor": "ready"
  },
  "uptime_seconds": 86400
}
```

---

## 📧 Text / Email Analysis

### Endpoint
```
POST /api/analyze/text
```

### Request Schema
```json
{
  "text": "string (required, max 50000 chars)",
  "language": "string (optional, default: 'en')"
}
```

### Request Example
```bash
curl -X POST http://localhost:8000/api/analyze/text \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Click here to verify your PayPal account immediately! Your account has been suspended due to unusual activity. Enter your credentials now: www.paypal-verify.tk"
  }'
```

### Response (200 OK)
```json
{
  "risk_score": 92,
  "status": "PHISHING",
  "confidence": 0.94,
  "classification": {
    "primary": "PHISHING",
    "secondary": ["credential_harvest", "urgency", "brand_impersonation"],
    "threat_level": "CRITICAL"
  },
  "indicators": {
    "urgency_detected": true,
    "credential_request": true,
    "brand_impersonation": true,
    "url_shortener": false,
    "suspicious_url": true,
    "financial_scam": false,
    "ransomware": false
  },
  "keywords": [
    "verify account",
    "suspended",
    "unusual activity",
    "credentials",
    "paypal"
  ],
  "detected_urls": [
    {
      "url": "www.paypal-verify.tk",
      "type": "suspicious",
      "tld": ".tk",
      "status": "PHISHING"
    }
  ],
  "reasons": [
    "Urgent language detected: 'immediately' (social engineering) - +25pts",
    "Credential request: 'Enter your credentials' - +30pts HIGH RISK",
    "Possible brand impersonation: 'paypal' - +20pts",
    "Suspicious URL pattern: .tk domain with 'paypal-verify' - +20pts",
    "Scam pattern - Account threat: 'suspended account' - +20pts"
  ],
  "ml_analysis": {
    "probability": 0.94,
    "confidence": 0.91,
    "feature_importance": {
      "urgency_keywords": 0.25,
      "credential_patterns": 0.30,
      "url_patterns": 0.22,
      "domain_patterns": 0.18,
      "linguistic_patterns": 0.05
    }
  },
  "heuristic_score": 92,
  "processing_time_ms": 145,
  "timestamp": "2026-05-20T14:35:22.456789Z"
}
```

### Response Fields Explanation

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | Integer (0-100) | Overall phishing risk |
| `status` | String | SAFE / SUSPICIOUS / PHISHING |
| `confidence` | Float (0-1) | Model confidence level |
| `classification.primary` | String | Main threat category |
| `classification.secondary` | Array | Additional threat types |
| `classification.threat_level` | String | LOW / MEDIUM / HIGH / CRITICAL |
| `indicators` | Object | Boolean flags for detected threats |
| `keywords` | Array | Flagged keywords from text |
| `detected_urls` | Array | URLs with individual analysis |
| `reasons` | Array | Human-readable explanations |
| `ml_analysis` | Object | ML model predictions & feature importance |
| `heuristic_score` | Integer | Pure heuristic scoring (0-100) |
| `processing_time_ms` | Integer | Response latency |

### Error Response (400 Bad Request)
```json
{
  "detail": "Text is required and must be between 1 and 50000 characters",
  "error_code": "INVALID_INPUT",
  "timestamp": "2026-05-20T14:35:22.456789Z"
}
```

---

## 🌐 URL Analysis

### Endpoint
```
POST /api/analyze/url
```

### Request Schema
```json
{
  "url": "string (required)",
  "deep_scan": "boolean (optional, default: false)"
}
```

### Request Example
```bash
curl -X POST http://localhost:8000/api/analyze/url \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://secure-amazon-login.tk/verify.php?user=admin",
    "deep_scan": true
  }'
```

### Response (200 OK)
```json
{
  "risk_score": 88,
  "status": "PHISHING",
  "url": "https://secure-amazon-login.tk/verify.php?user=admin",
  "domain_analysis": {
    "domain": "secure-amazon-login.tk",
    "tld": ".tk",
    "tld_risk": "HIGH",
    "is_subdomain": false,
    "subdomain": null,
    "domain_age_days": 3,
    "domain_age_risk": "CRITICAL",
    "registration_country": "Unknown"
  },
  "ssl_analysis": {
    "has_ssl": false,
    "is_valid": false,
    "certificate_issuer": null,
    "certificate_expiry": null,
    "protocol": "HTTP"
  },
  "reputation": {
    "status": "MALICIOUS",
    "votes_malicious": 15,
    "votes_clean": 2,
    "detection_ratio": "15/58",
    "last_scanned": "2026-05-20T12:00:00Z"
  },
  "ip_geolocation": {
    "ip_address": "185.220.101.45",
    "country": "Netherlands",
    "city": "Amsterdam",
    "asn": "AS39912"
  },
  "suspicious_patterns": [
    {
      "pattern": "brand_impersonation",
      "keyword": "amazon",
      "risk": "HIGH"
    },
    {
      "pattern": "suspicious_subdomain",
      "keyword": "secure-",
      "risk": "HIGH"
    },
    {
      "pattern": "suspicious_tld",
      "tld": ".tk",
      "risk": "HIGH"
    },
    {
      "pattern": "no_ssl",
      "detail": "HTTP protocol without encryption",
      "risk": "HIGH"
    }
  ],
  "page_content": {
    "title": null,
    "meta_description": null,
    "text_preview": "Sign in to your Amazon account...",
    "forms_detected": 1,
    "form_fields": ["email", "password"],
    "embedded_urls": 3
  },
  "typo_analysis": {
    "legitimate_domain": "amazon.com",
    "similarity_score": 0.72,
    "is_typosquatting": true
  },
  "url_components": {
    "scheme": "https",
    "host": "secure-amazon-login.tk",
    "path": "/verify.php",
    "query_string": "user=admin",
    "has_port": false,
    "port": null
  },
  "reasons": [
    "High-risk TLD detected: .tk (commonly used in phishing) - +30pts",
    "Brand impersonation: 'amazon' in domain - +25pts",
    "Suspicious domain pattern: 'secure-' prefix (fake credibility) - +20pts",
    "No SSL/TLS certificate (HTTP protocol) - +15pts",
    "New domain registered 3 days ago (very high risk) - +20pts",
    "Typosquatting detected: similarity to amazon.com - 72%"
  ],
  "processing_time_ms": 234,
  "timestamp": "2026-05-20T14:35:22.456789Z"
}
```

### HTTP Response Codes
| Code | Meaning |
|------|---------|
| 200 | Analysis successful |
| 400 | Invalid URL format |
| 429 | Rate limit exceeded |
| 500 | Server error |

---

## 📁 File Upload Analysis

### Endpoint
```
POST /api/analyze/file
```

### Request Type
```
Content-Type: multipart/form-data
```

### Allowed File Types
```
.txt, .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx, 
.zip, .rar, .csv, .eml, .apk
```

### Request Example (cURL)
```bash
curl -X POST http://localhost:8000/api/analyze/file \
  -F "file=@/path/to/document.pdf" \
  -F "scan_type=full"
```

### Request Example (JavaScript)
```javascript
const formData = new FormData();
formData.append('file', document.getElementById('fileInput').files[0]);
formData.append('scan_type', 'full');

const response = await fetch('http://localhost:8000/api/analyze/file', {
  method: 'POST',
  body: formData
});

const result = await response.json();
console.log(result);
```

### Response (200 OK)
```json
{
  "risk_score": 73,
  "status": "SUSPICIOUS",
  "file_metadata": {
    "filename": "invoice_2026.pdf",
    "file_type": "application/pdf",
    "file_size_bytes": 245632,
    "file_size_mb": 0.234,
    "mime_type": "application/pdf",
    "upload_timestamp": "2026-05-20T14:35:22.456789Z"
  },
  "hashing": {
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha256": "2c26b46911185131006745051b23b3b3...",
    "sha1": "356a192b7913b04c54574d18c28d46e6395428ab"
  },
  "threat_analysis": {
    "malware_detected": false,
    "ransomware_indicators": 1,
    "phishing_indicators": 3,
    "exploit_detected": false,
    "suspicious_scripts": 0
  },
  "extracted_text": "Invoice #2026-0051\n\nDear Valued Customer,\n\nPlease verify your payment information immediately at:\nhttps://secure-payment-verify.tk\n\nEnter your bank details and confirm transaction...",
  "text_analysis": {
    "risk_score": 73,
    "status": "SUSPICIOUS",
    "detected_keywords": [
      "verify payment",
      "immediate",
      "bank details",
      "confirm transaction"
    ],
    "detected_urls": [
      {
        "url": "https://secure-payment-verify.tk",
        "status": "PHISHING"
      }
    ]
  },
  "embedded_files": [
    {
      "name": "script.exe",
      "type": "executable",
      "size_bytes": 65536,
      "status": "FLAGGED"
    }
  ],
  "url_extraction": {
    "total_urls": 1,
    "suspicious_urls": 1,
    "phishing_urls": 1
  },
  "reasons": [
    "Extracted text contains phishing indicators: 'verify payment' - +25pts",
    "Malicious URL embedded in document - +30pts",
    "Embedded executable file detected: script.exe - +20pts",
    "Financial threat language: 'bank details', 'payment' - +15pts",
    "Urgency indicators: 'immediately' - +10pts"
  ],
  "processing_time_ms": 1850,
  "timestamp": "2026-05-20T14:35:22.456789Z"
}
```

### Response Codes
| Code | Meaning |
|------|---------|
| 200 | File analyzed successfully |
| 400 | Invalid file format or too large |
| 413 | File exceeds 50MB limit |
| 415 | Unsupported file type |
| 429 | Rate limit exceeded |

---

## 📱 APK Malware Analysis

### Endpoint
```
POST /api/analyze/apk
```

### Request Example
```bash
curl -X POST http://localhost:8000/api/analyze/apk \
  -F "file=@/path/to/app.apk"
```

### Response (200 OK)
```json
{
  "risk_score": 85,
  "status": "PHISHING",
  "apk_metadata": {
    "package_name": "com.fake.paypal",
    "app_name": "PayPal Secure",
    "version": "1.0.0",
    "version_code": 1,
    "min_sdk": 21,
    "target_sdk": 31,
    "permissions_count": 24
  },
  "permissions_analysis": {
    "dangerous_permissions": [
      {
        "permission": "android.permission.READ_SMS",
        "risk": "CRITICAL",
        "reason": "Can intercept SMS (2FA codes)"
      },
      {
        "permission": "android.permission.CAMERA",
        "risk": "HIGH",
        "reason": "Unauthorized camera access"
      },
      {
        "permission": "android.permission.RECORD_AUDIO",
        "risk": "HIGH",
        "reason": "Audio recording without consent"
      }
    ],
    "suspicious_permissions": 8,
    "unnecessary_permissions": 5
  },
  "signature_analysis": {
    "certificate_valid": false,
    "certificate_expired": true,
    "certificate_issuer": "Self-signed",
    "malware_signatures": [
      {
        "name": "Trojan.Banker.A",
        "detection_rate": 0.78,
        "severity": "CRITICAL"
      },
      {
        "name": "PUA.SpyApp.B",
        "detection_rate": 0.45,
        "severity": "HIGH"
      }
    ]
  },
  "urls_embedded": [
    {
      "url": "https://phishing-c2.ru",
      "type": "command_and_control",
      "status": "MALICIOUS"
    },
    {
      "url": "https://secure-payment.tk/login",
      "type": "phishing",
      "status": "PHISHING"
    }
  ],
  "reasons": [
    "Package name impersonates PayPal: 'com.fake.paypal' - +35pts",
    "Dangerous permissions detected: SMS reading (2FA interception) - +25pts",
    "Self-signed certificate (app authenticity unverified) - +15pts",
    "Trojan malware signature detected - +20pts",
    "Command & Control server embedded - +10pts"
  ],
  "processing_time_ms": 2340,
  "timestamp": "2026-05-20T14:35:22.456789Z"
}
```

---

## 🎙️ Audio Analysis

### Endpoint
```
POST /api/analyze/audio
```

### Supported Formats
`.wav`, `.mp3`, `.ogg`, `.flac`

### Request Example
```bash
curl -X POST http://localhost:8000/api/analyze/audio \
  -F "file=@/path/to/call_recording.wav"
```

### Response (200 OK)
```json
{
  "risk_score": 78,
  "status": "PHISHING",
  "audio_metadata": {
    "duration_seconds": 125,
    "format": "audio/wav",
    "sample_rate": 44100,
    "channels": 2,
    "file_size_bytes": 1105920
  },
  "transcription": {
    "text": "Hello, this is your bank calling. We detected unauthorized activity on your account. Please press 1 to verify your account details immediately.",
    "confidence": 0.92,
    "language": "en-US"
  },
  "text_analysis": {
    "risk_score": 78,
    "detected_threats": ["urgency", "credential_harvest", "social_engineering"],
    "keywords": ["bank", "unauthorized", "verify", "account", "immediately"]
  },
  "voice_analysis": {
    "emotion_detected": "urgency",
    "tone": "authoritative",
    "speech_rate": 145,
    "pauses": 3,
    "anomalies": ["artificial_sound", "background_noise"]
  },
  "reasons": [
    "Urgency language: 'immediately' (social engineering) - +25pts",
    "Bank impersonation: 'your bank calling' - +25pts",
    "Credential request: 'verify account details' - +30pts",
    "Artificial voice characteristics detected - +10pts",
    "Suspicious background noise (call center simulation) - +8pts"
  ],
  "processing_time_ms": 3450,
  "timestamp": "2026-05-20T14:35:22.456789Z"
}
```

---

## 🔄 Batch Analysis

### Endpoint
```
POST /api/batch/analyze
```

### Request Schema
```json
{
  "items": [
    {
      "type": "text",
      "content": "string"
    },
    {
      "type": "url",
      "content": "string"
    }
  ]
}
```

### Request Example
```bash
curl -X POST http://localhost:8000/api/batch/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      {
        "type": "text",
        "content": "Verify your account now!"
      },
      {
        "type": "url",
        "content": "https://fake-amazon.tk"
      },
      {
        "type": "text",
        "content": "Welcome to our newsletter."
      }
    ]
  }'
```

### Response (200 OK)
```json
{
  "batch_id": "batch_20260520_143522_abc123",
  "total_items": 3,
  "processed_items": 3,
  "results": [
    {
      "item_index": 0,
      "type": "text",
      "risk_score": 92,
      "status": "PHISHING"
    },
    {
      "item_index": 1,
      "type": "url",
      "risk_score": 88,
      "status": "PHISHING"
    },
    {
      "item_index": 2,
      "type": "text",
      "risk_score": 15,
      "status": "SAFE"
    }
  ],
  "summary": {
    "phishing_count": 2,
    "suspicious_count": 0,
    "safe_count": 1,
    "average_risk_score": 65
  },
  "processing_time_ms": 450,
  "timestamp": "2026-05-20T14:35:22.456789Z"
}
```

---

## ⚠️ Error Handling

### Common HTTP Status Codes

#### 400 Bad Request
```json
{
  "detail": "Invalid input: text cannot be empty",
  "error_code": "VALIDATION_ERROR",
  "field": "text"
}
```

#### 413 Payload Too Large
```json
{
  "detail": "File size exceeds 50MB limit",
  "error_code": "FILE_TOO_LARGE",
  "max_size_mb": 50
}
```

#### 429 Too Many Requests
```json
{
  "detail": "Rate limit exceeded. Max 100 requests per minute.",
  "error_code": "RATE_LIMIT_EXCEEDED",
  "retry_after_seconds": 45
}
```

#### 500 Internal Server Error
```json
{
  "detail": "An unexpected error occurred during analysis",
  "error_code": "INTERNAL_ERROR",
  "timestamp": "2026-05-20T14:35:22.456789Z"
}
```

---

## 🔐 Authentication (Future)

Reserved for API key authentication in production:
```bash
curl -X POST http://localhost:8000/api/analyze/text \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text": "..."}'
```

---

## 📊 Example Integration

### Python
```python
import requests
import json

API_BASE = "http://localhost:8000"

def analyze_email(email_text):
    response = requests.post(
        f"{API_BASE}/api/analyze/text",
        json={"text": email_text},
        timeout=10
    )
    return response.json()

# Usage
result = analyze_email("Verify your account now!")
print(f"Risk Score: {result['risk_score']}")
print(f"Status: {result['status']}")
```

### JavaScript
```javascript
const API_BASE = "http://localhost:8000";

async function analyzeText(text) {
  const response = await fetch(`${API_BASE}/api/analyze/text`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text })
  });
  return await response.json();
}

// Usage
const result = await analyzeText("Verify your account now!");
console.log(`Risk Score: ${result.risk_score}`);
```

---

**API Documentation Last Updated: May 20, 2026**  
**For support: support@zaifsecurity.pro**
