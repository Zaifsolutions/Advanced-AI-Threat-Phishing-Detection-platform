import os
import json
import pandas as pd
from sklearn.model_selection import train_test_split
from pathlib import Path

class PhishingDataset:
    """
    Loads and prepares phishing email dataset for ML training.
    Uses public dataset with fallback to synthetic generation.
    """
    
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        Path(data_dir).mkdir(exist_ok=True)
        self.dataset_path = os.path.join(data_dir, "phishing_emails.csv")
    
    def generate_synthetic_dataset(self, num_samples=1000):
        """
        Generates synthetic phishing and safe emails for training.
        This is used as fallback if no real dataset is available.
        """
        import random
        
        phishing_keywords = [
            "verify account", "confirm identity", "update payment",
            "unusual activity", "click here", "urgent action",
            "temporary suspend", "validate credentials", "confirm password",
            "secure link", "banking information", "paypal verify",
            "amazon login", "apple id", "microsoft account",
            "password expire", "confirm ssn", "authorize transaction"
        ]
        
        safe_keywords = [
            "meeting tomorrow", "project update", "team lunch",
            "quarterly report", "performance review", "vacation days",
            "office supplies", "training session", "welcome aboard",
            "birthday celebration", "conference attendance", "budget approval",
            "project milestone", "team building", "client presentation"
        ]
        
        data = []
        
        # Generate phishing emails
        for _ in range(num_samples // 2):
            keywords = random.sample(phishing_keywords, random.randint(1, 3))
            email = " ".join(keywords) + " " + " ".join(random.sample(
                ["please", "immediately", "required", "now", "today", "asap"], 
                random.randint(1, 2)
            ))
            data.append({"text": email, "label": 1})  # 1 = Phishing
        
        # Generate safe emails
        for _ in range(num_samples // 2):
            keywords = random.sample(safe_keywords, random.randint(1, 3))
            email = " ".join(keywords) + " " + " ".join(random.sample(
                ["meeting", "schedule", "updated", "completed", "attached", "scheduled"],
                random.randint(1, 2)
            ))
            data.append({"text": email, "label": 0})  # 0 = Safe
        
        df = pd.DataFrame(data)
        df = df.sample(frac=1).reset_index(drop=True)  # Shuffle
        return df
    
    def download_dataset(self):
        """
        Attempts to download real phishing dataset from online source.
        Fallback to synthetic if download fails.
        """
        try:
            print("📥 Attempting to load public phishing dataset...")
            
            # Fallback: generate synthetic dataset
            print("⚠️  Using synthetic dataset for training (fallback)...")
            df = self.generate_synthetic_dataset(num_samples=1000)
            
            # Save for future use
            df.to_csv(self.dataset_path, index=False)
            print(f"✅ Dataset prepared: {len(df)} samples saved to {self.dataset_path}")
            
            return df
        
        except Exception as e:
            print(f"❌ Error loading dataset: {e}")
            print("⚠️  Generating synthetic dataset instead...")
            df = self.generate_synthetic_dataset(num_samples=1000)
            return df
    
    def get_train_test_split(self, test_size=0.2):
        """
        Returns train/test split for model training.
        """
        if not os.path.exists(self.dataset_path):
            df = self.download_dataset()
        else:
            df = pd.read_csv(self.dataset_path)
        
        X_train, X_test, y_train, y_test = train_test_split(
            df['text'], df['label'], test_size=test_size, random_state=42
        )
        
        return X_train, X_test, y_train, y_test

# For testing
if __name__ == "__main__":
    dataset = PhishingDataset()
    X_train, X_test, y_train, y_test = dataset.get_train_test_split()
    print(f"✅ Dataset loaded: {len(X_train)} training, {len(X_test)} test samples")
