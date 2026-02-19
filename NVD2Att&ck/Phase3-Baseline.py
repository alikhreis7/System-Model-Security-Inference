import pandas as pd
import numpy as np
import pickle
import os
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
import joblib

# --- Configuration ---
DATA_DIR = "./processed_data_parent"
MODEL_DIR = "./models/baseline_parent"
MAX_FEATURES = 5000  # Vocabulary size (Top 5k words)

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class Phase3Baseline:
    def __init__(self):
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.classes = None
        self.model = None

    def load_data(self):
        logging.info("Loading preprocessed data...")
        
        # Load Text (Features)
        self.X_train = pd.read_csv(os.path.join(DATA_DIR, "train_text.csv"))['text'].fillna("").values
        self.X_test = pd.read_csv(os.path.join(DATA_DIR, "test_text.csv"))['text'].fillna("").values
        
        # Load Labels (Targets) - Compressed Numpy
        self.y_train = np.load(os.path.join(DATA_DIR, "y_train.npz"))['arr_0']
        self.y_test = np.load(os.path.join(DATA_DIR, "y_test.npz"))['arr_0']
        
        # Load Class Names
        with open(os.path.join(DATA_DIR, "mlb.pkl"), "rb") as f:
            mlb = pickle.load(f)
            self.classes = mlb.classes_
            
        logging.info(f"Data Loaded. Classes: {len(self.classes)}")

    def train_baseline(self):
        logging.info("Initializing TF-IDF + Logistic Regression Pipeline...")
        
        # The Pipeline
        # 1. TfidfVectorizer: Converts text to numbers (Word Counts weighted by rarity)
        # 2. OneVsRestClassifier: Wraps LogisticRegression to handle multi-label (183 binary models)
        self.model = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=MAX_FEATURES, stop_words='english')),
            ('clf', OneVsRestClassifier(LogisticRegression(solver='liblinear', class_weight='balanced')))
        ])
        
        logging.info("Training Model (this may take 1-2 minutes)...")
        self.model.fit(self.X_train, self.y_train)
        logging.info("Training Complete.")

    def evaluate(self):
        logging.info("Predicting on Test Set...")
        y_pred = self.model.predict(self.X_test)
        
        # Calculate Metrics
        # Micro: Global average (counts every correct prediction equally)
        # Macro: Class average (treats rare techniques same as common ones)
        micro_f1 = f1_score(self.y_test, y_pred, average='micro')
        macro_f1 = f1_score(self.y_test, y_pred, average='macro')
        
        logging.info("-" * 30)
        logging.info(f"BASELINE RESULTS")
        logging.info("-" * 30)
        logging.info(f"Micro F1-Score: {micro_f1:.4f} (Global Accuracy)")
        logging.info(f"Macro F1-Score: {macro_f1:.4f} (Rare Class Accuracy)")
        logging.info("-" * 30)
        
        # Detailed Report (First 20 classes to save space)
        # print(classification_report(self.y_test, y_pred, target_names=self.classes))
        
        return y_pred

    def save_model(self):
        if not os.path.exists(MODEL_DIR):
            os.makedirs(MODEL_DIR)
            
        model_path = os.path.join(MODEL_DIR, "tfidf_logreg.joblib")
        joblib.dump(self.model, model_path)
        logging.info(f"Model saved to {model_path}")

    def inference_test(self, text):
        """Quick check to see if it works on a raw string"""
        logging.info(f"Running Inference on: '{text[:50]}...'")
        prediction = self.model.predict([text])
        
        # Convert binary row back to class names
        # We need the MLB from Phase 2 to inverse transform, or just use indices
        pred_indices = np.where(prediction[0] == 1)[0]
        predicted_tags = [self.classes[i] for i in pred_indices]
        
        logging.info(f"Predicted Techniques: {predicted_tags}")

if __name__ == "__main__":
    baseline = Phase3Baseline()
    baseline.load_data()
    baseline.train_baseline()
    baseline.evaluate()
    baseline.save_model()
    
    # Simple Test
    baseline.inference_test("SQL injection vulnerability allows attacker to execute arbitrary commands.")