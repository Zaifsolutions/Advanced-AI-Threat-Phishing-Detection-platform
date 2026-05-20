"""
APK Analyzer - Basic Static Analysis for Android Malware Detection
Analyzes APK permissions, suspicious patterns, and malware indicators
"""

import re
import zipfile
from io import BytesIO

class APKAnalyzer:
    def __init__(self):
        # High-risk permissions that indicate potential malware
        self.high_risk_permissions = [
            'android.permission.SEND_SMS',  # Send SMS without user knowledge
            'android.permission.READ_SMS',  # Read SMS messages
            'android.permission.CALL_PHONE',  # Make calls
            'android.permission.READ_CONTACTS',  # Access contacts
            'android.permission.WRITE_CONTACTS',  # Modify contacts
            'android.permission.READ_CALL_LOG',  # Access call history
            'android.permission.WRITE_CALL_LOG',  # Modify call history
            'android.permission.ACCESS_FINE_LOCATION',  # Precise location tracking
            'android.permission.INSTALL_PACKAGES',  # Install apps silently
            'android.permission.DELETE_PACKAGES',  # Delete apps
            'android.permission.RECORD_AUDIO',  # Record audio (spyware indicator)
            'android.permission.CAMERA',  # Access camera
            'android.permission.ACCESS_WIFI_STATE',  # Wi-Fi info
            'android.permission.CHANGE_WIFI_STATE',  # Change Wi-Fi state
            'android.permission.INTERNET',  # Has been abused for C&C
            'android.permission.WRITE_EXTERNAL_STORAGE',  # Write to storage
        ]
        
        # Medium-risk permissions
        self.medium_risk_permissions = [
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.GET_ACCOUNTS',
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.READ_LOGS',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.GET_TASKS',
            'android.permission.REORDER_TASKS',
            'android.permission.VIBRATE',
            'android.permission.MODIFY_AUDIO_SETTINGS',
            'android.permission.BLUETOOTH',
            'android.permission.BLUETOOTH_ADMIN',
        ]
        
        # Known malware signatures and suspicious patterns
        self.malware_signatures = [
            'baseBot',  # Known botnet
            'Trojan',  # Generic trojan
            'Ransomware',  # Ransomware pattern
            'Spyware',  # Spyware pattern
            'Adware',  # Adware pattern
            'dropper',  # Dropper malware
            'rootkit',  # Rootkit pattern
            'worm',  # Worm pattern
            'virus',  # Virus pattern
        ]
        
        # Suspicious code patterns
        self.suspicious_patterns = [
            r'exec\s*\(',  # Runtime code execution
            r'reflection.*invoke',  # Reflection-based code execution
            r'http://.*command',  # Command & Control communication
            r'System\.load.*so',  # Native library loading (often used for evasion)
            r'ProcessBuilder',  # Process execution
            r'Runtime\.getRuntime',  # Runtime execution
            r'dalvik\.system\.DexClassLoader',  # Dynamic class loading
            r'DexFile\.loadDex',  # DEX file loading
            r'base64_decode',  # Obfuscation via base64
            r'cipher.*AES',  # Encrypted communication
            r'hidden_class',  # Hidden functionality
            r'C2_server',  # Command and control server reference
        ]
        
        # Suspicious package names
        self.suspicious_packages = [
            'com.fake',
            'com.virus',
            'com.malware',
            'com.spyware',
            'com.trojan',
            'com.admin.device',
            'com.system.helper',
            'com.google.fake',
            'com.facebook.fake',
        ]
    
    def analyze(self, file_content: bytes) -> dict:
        """
        Analyze APK file for malware indicators.
        """
        try:
            # Validate APK file signature
            if not file_content.startswith(b'PK'):
                return {
                    "risk_score": 0,
                    "verdict": "Invalid",
                    "reasons": ["File is not a valid APK (invalid signature)"],
                    "permissions": [],
                    "malware_indicators": [],
                    "suspicious_patterns_found": []
                }
            
            # Extract APK (it's a ZIP file)
            apk_zip = zipfile.ZipFile(BytesIO(file_content))
            
            # Read AndroidManifest.xml
            try:
                manifest_content = apk_zip.read('AndroidManifest.xml')
            except KeyError:
                return {
                    "risk_score": 40,
                    "verdict": "Suspicious",
                    "reasons": ["AndroidManifest.xml not found - corrupted or fake APK"],
                    "permissions": [],
                    "malware_indicators": [],
                    "suspicious_patterns_found": []
                }
            
            # Extract text content for analysis
            manifest_text = self._extract_text_from_binary(manifest_content)
            
            # Analyze permissions
            permissions = self._extract_permissions(manifest_text)
            risk_score = 0
            reasons = []
            
            # CRITICAL: INTERNET permission alone is NOT a threat
            # Only flag if dangerous permissions exist in risky combinations
            truly_dangerous_perms = [
                'android.permission.SEND_SMS',
                'android.permission.READ_SMS',
                'android.permission.CALL_PHONE',
                'android.permission.READ_CONTACTS',
                'android.permission.RECORD_AUDIO',
                'android.permission.CAMERA',
                'android.permission.INSTALL_PACKAGES',
                'android.permission.DELETE_PACKAGES',
            ]
            
            high_risk_found = [p for p in permissions if p in truly_dangerous_perms]
            if high_risk_found:
                # Only flag if multiple dangerous permissions exist
                if len(high_risk_found) >= 2:
                    risk_score += min(len(high_risk_found) * 10, 35)
                    reasons.append(f"Multiple dangerous permissions: {', '.join([p.split('.')[-1] for p in high_risk_found[:3]])}")
            
            # Check for malware signatures
            malware_found = self._detect_malware_signatures(manifest_text)
            if malware_found:
                risk_score += 50
                reasons.append(f"Possible malware indicators detected: {', '.join(malware_found)}")
            
            # Check for suspicious patterns (ONLY if other risks detected)
            suspicious_found = self._detect_suspicious_patterns(manifest_text)
            if suspicious_found and risk_score > 0:
                risk_score += 15
                reasons.append(f"Suspicious code patterns detected: {', '.join(suspicious_found[:2])}")
            
            # Check for suspicious package names
            package_name = self._extract_package_name(manifest_text)
            for suspicious in self.suspicious_packages:
                if suspicious.lower() in package_name.lower():
                    risk_score += 20
                    reasons.append(f"Suspicious package name pattern: '{suspicious}'")
                    break
            
            # Check for dangerous activity combinations
            if 'BOOT_COMPLETED' in manifest_text and 'SEND_SMS' in manifest_text:
                risk_score += 35
                reasons.append("Dangerous pattern: Auto-start + SMS sending (ransomware indicator)")
            
            # Cap score
            risk_score = min(risk_score, 100)
            
            # Determine verdict - ONLY based on ACTUAL evidence
            if risk_score == 0:
                verdict = "Safe"
                if not reasons:
                    reasons = ["No malware indicators or dangerous permission combinations detected. APK appears safe."]
            elif risk_score < 30:
                verdict = "Safe"
                if not reasons:
                    reasons = ["Standard app permissions - no elevated risk detected."]
            elif risk_score < 60:
                verdict = "Suspicious"
            else:
                verdict = "Malware Risk"
            
            if not reasons:
                reasons = ["Analysis complete - no significant threats detected."]
            
            return {
                "risk_score": risk_score,
                "verdict": verdict,
                "reasons": reasons,
                "permissions": permissions[:10],  # Top 10 permissions
                "malware_indicators": malware_found,
                "suspicious_patterns_found": suspicious_found
            }
        
        except Exception as e:
            return {
                "risk_score": 50,
                "verdict": "Error",
                "reasons": [f"Error analyzing APK: {str(e)}"],
                "permissions": [],
                "malware_indicators": [],
                "suspicious_patterns_found": []
            }
    
    def _extract_text_from_binary(self, data: bytes) -> str:
        """Extract readable text from binary data."""
        try:
            # Try to extract ASCII text from binary
            return ''.join([chr(b) for b in data if 32 <= b < 127])
        except:
            return ""
    
    def _extract_permissions(self, manifest_text: str) -> list:
        """Extract all permissions from manifest."""
        # Regex to find all permission declarations
        pattern = r'android\.permission\.[A-Z_]+'
        permissions = re.findall(pattern, manifest_text)
        return list(set(permissions))  # Remove duplicates
    
    def _extract_package_name(self, manifest_text: str) -> str:
        """Extract package name from manifest."""
        match = re.search(r'package=[\'\"]?([a-zA-Z0-9._]+)[\'\"]?', manifest_text)
        return match.group(1) if match else "unknown"
    
    def _detect_malware_signatures(self, manifest_text: str) -> list:
        """Detect known malware signatures."""
        found = []
        for signature in self.malware_signatures:
            if signature.lower() in manifest_text.lower():
                found.append(signature)
        return found
    
    def _detect_suspicious_patterns(self, manifest_text: str) -> list:
        """Detect suspicious code patterns."""
        found = []
        for pattern in self.suspicious_patterns:
            try:
                if re.search(pattern, manifest_text, re.IGNORECASE):
                    found.append(pattern[:30])  # Show first 30 chars
            except:
                pass
        return found
