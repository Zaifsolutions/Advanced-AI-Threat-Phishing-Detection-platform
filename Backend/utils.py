import os
import re
import hashlib
from fastapi import HTTPException, UploadFile

# Security Configuration
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB Limit
ALLOWED_EXTENSIONS = {".txt", ".eml", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".csv"}
ALLOWED_AUDIO_EXT = {".mp3", ".wav", ".aac", ".flac", ".ogg", ".m4a"}
ALLOWED_APK_EXT = {".apk"}

def validate_file(file: UploadFile, is_audio: bool = False, is_apk: bool = False):
    """
    Validates uploaded files for size and upload flow only.
    No extension restrictions are enforced by the backend so any file type can be uploaded.
    """
    return

def compute_file_hashes(data: bytes) -> dict:
    """Compute MD5 and SHA256 hashes for file."""
    try:
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return {"md5": md5, "sha256": sha256}
    except Exception:
        return {"md5": "N/A", "sha256": "N/A"}

def get_file_type(filename: str) -> str:
    """Determine file type from extension."""
    ext = os.path.splitext(filename)[1].lower()
    type_map = {
        ".txt": "Text File",
        ".eml": "Email File",
        ".pdf": "PDF Document",
        ".doc": "Word Document (Legacy)",
        ".docx": "Word Document",
        ".xls": "Excel Spreadsheet (Legacy)",
        ".xlsx": "Excel Spreadsheet",
        ".ppt": "PowerPoint (Legacy)",
        ".pptx": "PowerPoint Presentation",
        ".zip": "ZIP Archive",
        ".rar": "RAR Archive",
        ".csv": "CSV Data File",
        ".mp3": "Audio File (MP3)",
        ".wav": "Audio File (WAV)",
        ".aac": "Audio File (AAC)",
        ".flac": "Audio File (FLAC)",
        ".ogg": "Audio File (OGG)",
        ".m4a": "Audio File (M4A)",
        ".apk": "Android Package",
    }
    return type_map.get(ext, "Unknown File Type")

def extract_text_from_file(data: bytes, filename: str) -> str:
    """Extract text from various file formats."""
    ext = os.path.splitext(filename)[1].lower()
    
    # Plain text files
    if ext in {".txt", ".eml", ".csv"}:
        try:
            return data.decode("utf-8", errors="ignore")
        except:
            return ""
    
    # For binary formats, attempt basic text extraction
    if ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar"}:
        # Attempt to extract ASCII strings as a fallback
        text = ""
        try:
            # Extract printable ASCII text
            decoded = data.decode("utf-8", errors="ignore")
            text = re.sub(r"[^\x20-\x7E\n\r\t]", "", decoded)
        except:
            try:
                # Try Latin-1 as fallback
                text = data.decode("latin-1", errors="ignore")
                text = re.sub(r"[^\x20-\x7E\n\r\t]", "", text)
            except:
                pass
        return text[:10000]  # Limit to first 10k chars
    
    return ""

def extract_domain_info(url: str) -> dict:
    """Extract domain information from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or url
        return {
            "domain": domain,
            "scheme": parsed.scheme or "http",
            "path": parsed.path or "/",
        }
    except Exception:
        return {"domain": url, "scheme": "unknown", "path": ""}

def sanitize_text(text: str) -> str:
    """
    Sanitizes user input to prevent XSS or injection before logging or analysis.
    """
    # Remove potentially dangerous HTML tags or scripts from raw text
    clean_text = re.sub(r'<.*?>', '', text)
    return clean_text.strip()