"""
Audio Analyzer - Convert speech to text and analyze for phishing indicators
Uses speech recognition and analyzes the resulting text
"""

import io
import wave
from typing import Optional

class AudioAnalyzer:
    def __init__(self):
        # Try to import speech recognition
        self.speech_available = False
        try:
            import speech_recognition as sr
            self.recognizer = sr.Recognizer()
            self.speech_available = True
        except ImportError:
            self.recognizer = None
            self.speech_available = False
        
        # Phishing indicators to listen for in audio
        self.phishing_phrases = [
            'verify your account',
            'confirm your password',
            'update your information',
            'unusual activity',
            'act now',
            'immediately',
            'urgent',
            'click the link',
            'provide your credentials',
            'banking information',
            'credit card number',
            'social security',
            'personal information',
            'suspended account',
            'locked account',
        ]
    
    def analyze(self, file_content: bytes) -> dict:
        """
        Analyze audio file for phishing content.
        Converts speech to text and analyzes it.
        """
        try:
            # Check file size (limit to 25MB)
            if len(file_content) > 25 * 1024 * 1024:
                return {
                    "transcription": "",
                    "risk_score": 0,
                    "status": "Error",
                    "reasons": ["Audio file too large (max 25MB)"],
                    "phishing_phrases_found": [],
                    "confidence": 0
                }
            
            # Validate audio file
            if not self._is_valid_audio(file_content):
                return {
                    "transcription": "",
                    "risk_score": 0,
                    "status": "Error",
                    "reasons": ["Invalid audio file format (supported: WAV, MP3)"],
                    "phishing_phrases_found": [],
                    "confidence": 0
                }
            
            # Try speech recognition
            if self.speech_available:
                transcription = self._transcribe_audio(file_content)
            else:
                # Fallback: return information about the limitation
                return {
                    "transcription": "",
                    "risk_score": 0,
                    "status": "Pending",
                    "reasons": ["Speech recognition unavailable. Install: pip install SpeechRecognition pydub"],
                    "phishing_phrases_found": [],
                    "confidence": 0
                }
            
            if not transcription:
                return {
                    "transcription": "",
                    "risk_score": 0,
                    "status": "Error",
                    "reasons": ["Could not transcribe audio (unclear speech or unsupported language)"],
                    "phishing_phrases_found": [],
                    "confidence": 0
                }
            
            # Analyze transcription for phishing phrases
            return self._analyze_transcription(transcription)
        
        except Exception as e:
            return {
                "transcription": "",
                "risk_score": 0,
                "status": "Error",
                "reasons": [f"Error analyzing audio: {str(e)}"],
                "phishing_phrases_found": [],
                "confidence": 0
            }
    
    def _is_valid_audio(self, file_content: bytes) -> bool:
        """Check if file is valid audio format."""
        try:
            # Check WAV header
            if file_content.startswith(b'RIFF') and b'WAVE' in file_content[:12]:
                return True
            # Check MP3 header
            if file_content.startswith(b'ID3') or file_content.startswith(b'\xff\xfb'):
                return True
            return False
        except:
            return False
    
    def _transcribe_audio(self, file_content: bytes) -> Optional[str]:
        """Transcribe audio to text using speech recognition."""
        try:
            import speech_recognition as sr
            
            # Convert bytes to audio file
            audio_file = io.BytesIO(file_content)
            
            # Use AudioFile for file-based transcription
            with sr.AudioFile(audio_file) as source:
                audio = self.recognizer.record(source)
            
            # Try Google Speech Recognition first
            try:
                text = self.recognizer.recognize_google(audio)
                return text
            except sr.UnknownValueError:
                # Audio was not understood
                return None
            except sr.RequestError:
                # Try fallback recognizer
                try:
                    text = self.recognizer.recognize_sphinx(audio)
                    return text
                except:
                    return None
        
        except Exception as e:
            print(f"Transcription error: {str(e)}")
            return None
    
    def _analyze_transcription(self, text: str) -> dict:
        """Analyze transcribed text for phishing indicators."""
        from analyzer import TextAnalyzer  # Use existing text analyzer
        
        # Use the TextAnalyzer for consistency
        analyzer = TextAnalyzer()
        result = analyzer.analyze_text(text)
        
        # Enhance with audio-specific indicators
        phishing_phrases_found = []
        for phrase in self.phishing_phrases:
            if phrase.lower() in text.lower():
                phishing_phrases_found.append(phrase)
        
        # Return enhanced analysis
        return {
            "transcription": text,
            "risk_score": result["risk_score"],
            "status": result["status"],
            "reasons": result["reasons"],
            "phishing_phrases_found": phishing_phrases_found,
            "confidence": result["ml_confidence"] if result.get("ml_confidence") else 0
        }
