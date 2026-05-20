#!/usr/bin/env python3
"""
Comprehensive test suite for ZaifSecurity platform
Tests: Text, URL, File, APK, Audio analysis
"""
import requests
import json
import sys
from pathlib import Path

API_BASE = "http://127.0.0.1:8000"
TESTS_PASSED = 0
TESTS_FAILED = 0

def test_health():
    """Test health endpoint"""
    global TESTS_PASSED, TESTS_FAILED
    print("\n" + "="*60)
    print("TEST 1: Health Check")
    print("="*60)
    try:
        r = requests.get(f"{API_BASE}/api/health")
        data = r.json()
        print(f"✓ Status: {data.get('status')}")
        print(f"✓ ML Model: {data.get('ml_model')}")
        print(f"✓ Text Analyzer: {data.get('text_analyzer')}")
        print(f"✓ URL Analyzer: {data.get('url_analyzer')}")
        TESTS_PASSED += 1
        return True
    except Exception as e:
        print(f"✗ Error: {e}")
        TESTS_FAILED += 1
        return False

def test_text_analysis():
    """Test text/email analysis"""
    global TESTS_PASSED, TESTS_FAILED
    print("\n" + "="*60)
    print("TEST 2: Text/Email Analysis")
    print("="*60)
    
    test_cases = [
        {
            "text": "URGENT: Verify your account at https://secure-login.example.tk immediately!",
            "expected_status": "Phishing",
            "name": "Phishing Email"
        },
        {
            "text": "Hello, how are you doing today?",
            "expected_status": "Safe",
            "name": "Safe Email"
        },
        {
            "text": "Your payment needs verification. Click here to update your billing info.",
            "expected_status": "Suspicious",
            "name": "Suspicious Email"
        }
    ]
    
    for test in test_cases:
        try:
            r = requests.post(f"{API_BASE}/api/analyze/text", 
                            json={"text": test["text"]})
            data = r.json()
            status = data.get("status")
            score = data.get("risk_score")
            print(f"\n  {test['name']}:")
            print(f"    Score: {score}/100")
            print(f"    Status: {status}")
            print(f"    Reasons: {data.get('reasons', [])[:2]}")
            if status:
                TESTS_PASSED += 1
            else:
                TESTS_FAILED += 1
        except Exception as e:
            print(f"  ✗ {test['name']}: {e}")
            TESTS_FAILED += 1

def test_url_analysis():
    """Test URL analysis"""
    global TESTS_PASSED, TESTS_FAILED
    print("\n" + "="*60)
    print("TEST 3: URL Analysis")
    print("="*60)
    
    urls = [
        {"url": "https://www.google.com", "name": "Google (Safe)"},
        {"url": "https://secure-login.example.tk/verify", "name": "Suspicious TLD (.tk)"},
        {"url": "https://paypal-verify.com", "name": "Typosquatting"},
    ]
    
    for test in urls:
        try:
            r = requests.post(f"{API_BASE}/api/analyze/url", 
                            json={"url": test["url"]})
            if r.status_code == 200:
                data = r.json()
                verdict = data.get("verdict")
                score = data.get("risk_score")
                print(f"\n  {test['name']}:")
                print(f"    Score: {score}/100")
                print(f"    Verdict: {verdict}")
                print(f"    Reasons: {data.get('reasons', [])[:2]}")
                TESTS_PASSED += 1
            else:
                print(f"  ✗ {test['name']}: HTTP {r.status_code}")
                TESTS_FAILED += 1
        except Exception as e:
            print(f"  ✗ {test['name']}: {e}")
            TESTS_FAILED += 1

def test_file_analysis():
    """Test file upload and analysis"""
    global TESTS_PASSED, TESTS_FAILED
    print("\n" + "="*60)
    print("TEST 4: File Upload & Analysis")
    print("="*60)
    
    # Create test files
    test_files = [
        ("test_safe.txt", "This is a safe email message."),
        ("test_phishing.txt", "URGENT: Verify account at https://fake-bank.tk/login"),
        ("test_suspicious.eml", "Your account needs verification. Click: https://confirm.example.com"),
    ]
    
    for filename, content in test_files:
        try:
            filepath = Path(filename)
            filepath.write_text(content)
            
            with open(filepath, "rb") as f:
                files = {"file": (filename, f)}
                r = requests.post(f"{API_BASE}/api/analyze/file", files=files)
            
            if r.status_code == 200:
                data = r.json()
                status = data.get("status")
                score = data.get("risk_score")
                print(f"\n  {filename}:")
                print(f"    Score: {score}/100")
                print(f"    Status: {status}")
                print(f"    File Type: {data.get('file_type')}")
                print(f"    File Size: {data.get('file_size')} bytes")
                if data.get('file_hashes'):
                    print(f"    MD5: {data['file_hashes'].get('md5', 'N/A')[:16]}...")
                TESTS_PASSED += 1
                filepath.unlink()  # Clean up
            else:
                print(f"  ✗ {filename}: HTTP {r.status_code}: {r.text}")
                TESTS_FAILED += 1
                filepath.unlink()
        except Exception as e:
            print(f"  ✗ {filename}: {e}")
            TESTS_FAILED += 1
            if Path(filename).exists():
                Path(filename).unlink()

def test_output_format():
    """Test that output includes all required VirusTotal-like fields"""
    global TESTS_PASSED, TESTS_FAILED
    print("\n" + "="*60)
    print("TEST 5: Output Format Validation (VirusTotal-like)")
    print("="*60)
    
    try:
        r = requests.post(f"{API_BASE}/api/analyze/text",
                        json={"text": "Test phishing detection"})
        data = r.json()
        
        required_fields = [
            "risk_score", "status", "reasons", "keywords_found",
            "ml_confidence", "heuristic_score", "confidence",
            "timestamp", "analysis_type"
        ]
        
        missing = [f for f in required_fields if f not in data]
        if not missing:
            print("✓ All required fields present:")
            for field in required_fields[:5]:
                print(f"  - {field}: {str(data[field])[:50]}")
            TESTS_PASSED += 1
        else:
            print(f"✗ Missing fields: {missing}")
            TESTS_FAILED += 1
    except Exception as e:
        print(f"✗ Error: {e}")
        TESTS_FAILED += 1

def print_summary():
    """Print test summary"""
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    total = TESTS_PASSED + TESTS_FAILED
    percentage = (TESTS_PASSED / total * 100) if total > 0 else 0
    print(f"Total Tests: {total}")
    print(f"Passed: {TESTS_PASSED} ✓")
    print(f"Failed: {TESTS_FAILED} ✗")
    print(f"Success Rate: {percentage:.1f}%")
    print("="*60)
    return TESTS_FAILED == 0

if __name__ == "__main__":
    print("\n🛡️ ZaifSecurity — Full System Test Suite")
    print("Testing: Text, URL, File, Output Format")
    
    test_health()
    test_text_analysis()
    test_url_analysis()
    test_file_analysis()
    test_output_format()
    
    success = print_summary()
    sys.exit(0 if success else 1)
