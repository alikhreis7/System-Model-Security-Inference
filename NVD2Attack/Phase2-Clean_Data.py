import pandas as pd
import numpy as np
import re
import ast
import pickle
import logging
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.model_selection import train_test_split
from collections import Counter

# --- Configuration ---
INPUT_FILE = "phase1_dataset_parent_only.csv"
OUTPUT_DIR = "./processed_data_parent"
MIN_SAMPLES_PER_CLASS = 10  # Drop techniques with fewer than X examples
TEST_SIZE = 0.2
RANDOM_STATE = 420

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class Phase2Preprocessor:
    def __init__(self):
        self.df = None
        self.mlb = MultiLabelBinarizer()
        
    def load_data(self):
        logging.info(f"Loading data from {INPUT_FILE}...")
        if not os.path.exists(INPUT_FILE):
            raise FileNotFoundError(f"{INPUT_FILE} not found. Did Phase 1 finish?")
        
        self.df = pd.read_csv(INPUT_FILE)
        
        # Convert string representation of lists "['T1', 'T2']" back to actual lists
        self.df['labels'] = self.df['labels'].apply(lambda x: ast.literal_eval(x) if isinstance(x, str) else x)
        
        logging.info(f"Loaded {len(self.df)} rows.")

    def clean_text(self, text):
        """
        Removes URLs, CVE IDs, hex codes, and extra whitespace.
        We keep the text mostly intact for Contextual Embeddings (BERT) later,
        but remove specific artifacts that cause overfitting.
        """
        if not isinstance(text, str):
            return ""
        
        # 1. Lowercase
        text = text.lower()
        
        # 2. Remove CVE IDs (Data Leakage Prevention)
        # e.g., "CVE-2021-44228" -> "vulnerability"
        text = re.sub(r'cve-\d{4}-\d{4,7}', 'vulnerability', text)
        
        # 3. Remove URLs
        text = re.sub(r'http\S+|www\.\S+', '', text)
        
        # 4. Remove Hex Codes / Memory Addresses (common in exploits)
        # e.g., 0x41414141
        text = re.sub(r'0x[a-f0-9]+', '', text)
        
        # 5. Remove special chars but keep hyphens/dots (useful for versions)
        text = re.sub(r'[^a-z0-9\s\-\.]', '', text)
        
        # 6. Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text

    def preprocess_text(self):
        logging.info("Cleaning text descriptions...")
        # Create a clean column, keep original for reference
        self.df['clean_text'] = self.df['text'].apply(self.clean_text)
        
        # Drop rows that became empty after cleaning
        initial_len = len(self.df)
        self.df = self.df[self.df['clean_text'].str.len() > 10]
        logging.info(f"Dropped {initial_len - len(self.df)} empty/short rows.")

    def filter_rare_classes(self):
        """
        Implements the 'Balancing' strategy.
        Removes labels that appear fewer than MIN_SAMPLES_PER_CLASS times.
        """
        logging.info(f"Filtering rare classes (Threshold: {MIN_SAMPLES_PER_CLASS})...")
        
        # Flatten all labels to count frequency
        all_labels = [label for sublist in self.df['labels'] for label in sublist]
        counts = Counter(all_labels)
        
        # Identify valid labels
        valid_labels = {lbl for lbl, count in counts.items() if count >= MIN_SAMPLES_PER_CLASS}
        dropped_labels = {lbl for lbl, count in counts.items() if count < MIN_SAMPLES_PER_CLASS}
        
        logging.info(f"Found {len(valid_labels)} valid techniques. Dropping {len(dropped_labels)} rare ones.")
        
        # Filter the label lists in the dataframe
        def filter_row_labels(label_list):
            return [lbl for lbl in label_list if lbl in valid_labels]
        
        self.df['filtered_labels'] = self.df['labels'].apply(filter_row_labels)
        
        # Drop rows that now have NO labels (because all their labels were rare)
        initial_len = len(self.df)
        self.df = self.df[self.df['filtered_labels'].map(len) > 0]
        logging.info(f"Dropped {initial_len - len(self.df)} rows that lost all labels after filtering.")

    def encode_labels(self):
        """
        Converts lists of strings to a binary matrix.
        ['T1', 'T2'] -> [1, 1, 0, 0, ...]
        """
        logging.info("Binarizing labels (One-Hot Encoding)...")
        
        # Fit MultiLabelBinarizer
        y = self.mlb.fit_transform(self.df['filtered_labels'])
        
        # Get class names
        classes = self.mlb.classes_
        logging.info(f"Final Class Count: {len(classes)}")
        
        return y, classes

    def save_artifacts(self, y):
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
            
        logging.info("Splitting Train/Test and saving artifacts...")
        
        # Split Data
        X = self.df['clean_text'].values
        
        # We use a standard random split here. 
        # (For strict multi-label stratification, 'iterative-stratification' lib is better, 
        # but standard split is usually fine for N > 5000).
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE
        )
        
        # Save Metadata (Class Names)
        with open(os.path.join(OUTPUT_DIR, "mlb.pkl"), "wb") as f:
            pickle.dump(self.mlb, f)
            
        # Save Datasets (Parquet is faster/smaller than CSV for arrays, but CSV is human readable. 
        # We will save as Numpy arrays for the matrices and CSV for text)
        
        # Save Text
        pd.DataFrame(X_train, columns=['text']).to_csv(os.path.join(OUTPUT_DIR, "train_text.csv"), index=False)
        pd.DataFrame(X_test, columns=['text']).to_csv(os.path.join(OUTPUT_DIR, "test_text.csv"), index=False)
        
        # Save Label Matrices (Compressed Numpy)
        np.savez_compressed(os.path.join(OUTPUT_DIR, "y_train.npz"), y_train)
        np.savez_compressed(os.path.join(OUTPUT_DIR, "y_test.npz"), y_test)
        
        logging.info(f"Processing Complete.")
        logging.info(f"Train Size: {len(X_train)}")
        logging.info(f"Test Size: {len(X_test)}")
        logging.info(f"Outputs saved to {OUTPUT_DIR}/")

if __name__ == "__main__":
    import os
    
    preprocessor = Phase2Preprocessor()
    preprocessor.load_data()
    preprocessor.preprocess_text()
    preprocessor.filter_rare_classes()
    y_matrix, class_names = preprocessor.encode_labels()
    preprocessor.save_artifacts(y_matrix)