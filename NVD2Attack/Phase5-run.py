import torch
import pickle
import numpy as np
import logging
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# --- Configuration ---
MODEL_PATH = "./models/securebert_finetuned"  # Where Phase 4 saved the best model
DATA_DIR = "./processed_data"        # Where Phase 2 saved the MLB
MAX_LEN = 256
CONFIDENCE_THRESHOLD = 0.5           # Only show predictions with > 50% confidence

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(message)s")  # Simpler format for CLI tool

class ATTACKPredictor:
    def __init__(self):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logging.info(f"Loading Inference Engine on {self.device}...")
        
        self._load_artifacts()

    def _load_artifacts(self):
        try:
            # 1. Load Tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
            
            # 2. Load Label Binarizer (to get class names back)
            with open(f"{DATA_DIR}/mlb.pkl", "rb") as f:
                self.mlb = pickle.load(f)
            self.classes = self.mlb.classes_
            
            # 3. Load Model
            self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
            self.model.to(self.device)
            self.model.eval()
            
            logging.info("Model loaded successfully.")
            logging.info(f"Vocabulary: {self.tokenizer.vocab_size} words")
            logging.info(f"Target Classes: {len(self.classes)} Techniques")
            
        except Exception as e:
            logging.error(f"Failed to load artifacts: {e}")
            exit(1)

    def predict(self, text):
        # Preprocess
        encoding = self.tokenizer(
            text,
            add_special_tokens=True,
            max_length=MAX_LEN,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt'
        )
        
        input_ids = encoding['input_ids'].to(self.device)
        attention_mask = encoding['attention_mask'].to(self.device)

        # Inference
        with torch.no_grad():
            outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            probs = torch.sigmoid(logits).cpu().numpy()[0] # Convert to probabilities (0.0 - 1.0)

        # Decode Results
        results = {}
        for idx, score in enumerate(probs):
            if score > 0.01: # Optimization: ignore practically zero chance
                results[self.classes[idx]] = float(score)

        # Sort by confidence
        sorted_results = sorted(results.items(), key=lambda x: x[1], reverse=True)
        
        return sorted_results

    def format_output(self, predictions):
        print("\n" + "="*40)
        print(f"PREDICTED ATT&CK TECHNIQUES")
        print("="*40)
        
        found_any = False
        
        # 1. High Confidence Matches
        for tech, score in predictions:
            if score >= CONFIDENCE_THRESHOLD:
                print(f"✅  {tech}  (Confidence: {score:.1%})")
                found_any = True
        
        if not found_any:
            print("⚠️  No high-confidence matches found.")
            print("   Top 3 Guesses:")
            for tech, score in predictions[:3]:
                 print(f"   ?  {tech}  ({score:.1%})")
        
        print("-" * 40 + "\n")

# --- Interactive Loop ---
if __name__ == "__main__":
    engine = ATTACKPredictor()
    
    print("\n" + "*"*50)
    print(" MITRE ATT&CK MAPPER - INFERENCE MODE")
    print(" Type 'exit' to quit.")
    print("*"*50 + "\n")
    
    while True:
        user_input = input("Enter CVE Description: ")
        if user_input.lower() in ['exit', 'quit']:
            break
            
        if len(user_input.strip()) < 10:
            print("[!] Description too short. Please be more specific.")
            continue
            
        preds = engine.predict(user_input)
        engine.format_output(preds)