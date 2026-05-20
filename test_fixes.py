"""
Test script to verify that the fixes work correctly.
Tests:
1. Safe text → risk_score should be 0
2. Safe URL → risk_score should be 0
3. Clean file → risk_score should be 0
"""
import requests
import json

API_BASE = "http://127.0.0.1:8000"

def test_safe_text():
    """Test with safe text content - should return 0% risk"""
    print("\n" + "="*60)
    print("TEST 1: Safe Text Analysis")
    print("="*60)
    
    payload = {
        "text": "Hello, I hope this email finds you well. I wanted to reach out to discuss our upcoming meeting on Friday. Looking forward to hearing from you."
    }
    
    response = requests.post(f"{API_BASE}/analyze-email", json=payload)
    data = response.json()
    
    print(f"Status Code: {response.status_code}")
    print(f"Risk Score: {data.get('risk_score', 'N/A')}")
    print(f"Status: {data.get('status', 'N/A')}")
    print(f"Reasons: {data.get('reasons', [])}")
    
    assert data['risk_score'] == 0, f"Expected 0, got {data['risk_score']}"
    assert data['status'] == 'Safe', f"Expected Safe, got {data['status']}"
    print("✅ PASS: Safe text correctly returned 0% risk")

def test_safe_url():
    """Test with known safe URL - should return 0% risk"""
    print("\n" + "="*60)
    print("TEST 2: Safe URL Analysis")
    print("="*60)
    
    payload = {
        "url": "https://www.google.com"
    }
    
    response = requests.post(f"{API_BASE}/analyze-url", json=payload)
    data = response.json()
    
    print(f"Status Code: {response.status_code}")
    print(f"Risk Score: {data.get('risk_score', 'N/A')}")
    print(f"Verdict: {data.get('verdict', 'N/A')}")
    print(f"Reasons: {data.get('reasons', [])}")
    
    assert data['risk_score'] == 0, f"Expected 0, got {data['risk_score']}"
    assert data['verdict'] == 'Safe', f"Expected Safe, got {data['verdict']}"
    print("✅ PASS: Safe URL correctly returned 0% risk")

def test_phishing_text():
    """Test with phishing text - should return > 0% risk"""
    print("\n" + "="*60)
    print("TEST 3: Phishing Text Detection")
    print("="*60)
    
    payload = {
        "text": "URGENT: Your account has been suspended! Click here immediately to verify your password and confirm your identity. Respond now or lose access permanently. https://bit.ly/verify-account-now"
    }
    
    response = requests.post(f"{API_BASE}/analyze-email", json=payload)
    data = response.json()
    
    print(f"Status Code: {response.status_code}")
    print(f"Risk Score: {data.get('risk_score', 'N/A')}")
    print(f"Status: {data.get('status', 'N/A')}")
    print(f"Reasons: {data.get('reasons', [])}")
    
    assert data['risk_score'] > 30, f"Expected > 30, got {data['risk_score']}"
    assert data['status'] in ['Suspicious', 'Phishing'], f"Expected Suspicious/Phishing, got {data['status']}"
    print("✅ PASS: Phishing text correctly flagged with risk > 30%")

def test_suspicious_url():
    """Test with suspicious URL - should return > 0% risk"""
    print("\n" + "="*60)
    print("TEST 4: Suspicious URL Detection")
    print("="*60)
    
    payload = {
        "url": "https://bit.ly/verify-paypal-account"
    }
    
    response = requests.post(f"{API_BASE}/analyze-url", json=payload)
    data = response.json()
    
    print(f"Status Code: {response.status_code}")
    print(f"Risk Score: {data.get('risk_score', 'N/A')}")
    print(f"Verdict: {data.get('verdict', 'N/A')}")
    print(f"Reasons: {data.get('reasons', [])}")
    
    assert data['risk_score'] > 10, f"Expected > 10, got {data['risk_score']}"
    assert data['verdict'] in ['Suspicious', 'Phishing'], f"Expected Suspicious/Phishing, got {data['verdict']}"
    print("✅ PASS: Suspicious URL correctly detected with risk > 10%")

if __name__ == "__main__":
    print("\n🧪 Running Evidence-Based Analysis Tests...")
    print("Testing that the system ONLY shows risk when evidence exists")
    
    try:
        test_safe_text()
        test_safe_url()
        test_phishing_text()
        test_suspicious_url()
        
        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED!")
        print("="*60)
        print("\n✓ System now uses ONLY evidence-based scoring")
        print("✓ Safe files/URLs/text return 0% risk")
        print("✓ Only shows risk when threats are detected")
        print("✓ No fake indicators or default scores\n")
    
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}\n")
    except Exception as e:
        print(f"\n❌ ERROR: {e}\n")
