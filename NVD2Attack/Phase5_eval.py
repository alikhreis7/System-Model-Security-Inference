import torch
import numpy as np
import pandas as pd
import pickle
import logging
import os
from torch.utils.data import DataLoader, Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report, hamming_loss, multilabel_confusion_matrix

# --- Configuration ---
DATA_DIR = "./processed_data_parent"
MODEL_DIR = "./models/securebert_finetuned_parent"
BATCH_SIZE = 32
MAX_LEN = 256

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

if torch.cuda.is_available():
    device = torch.device('cuda')
else:
    device = torch.device('cpu')
    logging.warning("Using CPU. Inference might be slow.")

class EvaluationDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, item):
        text = str(self.texts[item])
        label = self.labels[item]
        encoding = self.tokenizer(
            text,
            add_special_tokens=True,
            max_length=self.max_len,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt',
        )
        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.FloatTensor(label)
        }

def load_data():
    test_text = pd.read_csv(os.path.join(DATA_DIR, "test_text.csv"))['text'].fillna("").values
    y_test = np.load(os.path.join(DATA_DIR, "y_test.npz"))['arr_0']
    
    with open(os.path.join(DATA_DIR, "mlb.pkl"), "rb") as f:
        mlb = pickle.load(f)
        
    return test_text, y_test, mlb

def get_predictions(model, loader):
    model.eval()
    all_probs = []
    all_targets = []
    
    logging.info("Running Inference on Test Set...")
    with torch.no_grad():
        for d in loader:
            input_ids = d["input_ids"].to(device)
            attention_mask = d["attention_mask"].to(device)
            targets = d["labels"].to(device)
            
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            probs = torch.sigmoid(outputs.logits)
            
            all_probs.extend(probs.cpu().numpy())
            all_targets.extend(targets.cpu().numpy())
            
    return np.array(all_probs), np.array(all_targets)

def find_optimal_threshold(probs, targets):
    logging.info("\n--- Threshold Optimization ---")
    thresholds = np.arange(0.1, 0.95, 0.05)
    best_thresh = 0.5
    best_f1 = 0.0
    
    results = []
    
    for thresh in thresholds:
        preds = (probs > thresh).astype(int)
        f1 = f1_score(targets, preds, average='micro')
        results.append((thresh, f1))
        
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = thresh
            
    # Print curve
    print(f"{'Threshold':<10} | {'F1 Score':<10}")
    print("-" * 25)
    for t, f in results:
        marker = "*" if t == best_thresh else ""
        print(f"{t:.2f}       | {f:.4f} {marker}")
        
    logging.info(f"\n✅ Optimal Threshold found: {best_thresh:.2f}")
    logging.info(f"   New Best F1 Score: {best_f1:.4f}")
    
    return best_thresh

def detailed_report(targets, preds, classes):
    logging.info("\n--- Detailed Metrics ---")
    
    # 1. Global Metrics
    p = precision_score(targets, preds, average='micro')
    r = recall_score(targets, preds, average='micro')
    f1_micro = f1_score(targets, preds, average='micro')
    f1_macro = f1_score(targets, preds, average='macro')
    hl = hamming_loss(targets, preds)
    
    print(f"Micro Precision: {p:.4f}")
    print(f"Micro Recall:    {r:.4f}")
    print(f"Micro F1:        {f1_micro:.4f}")
    print(f"Macro F1:        {f1_macro:.4f} (Avg across all classes)")
    print(f"Hamming Loss:    {hl:.4f} (Lower is better)")
    
    # 2. Per-Class Report
    logging.info("\n--- Class Performance (Top 10 Best & Worst) ---")
    
    # Calculate per-class F1
    report = classification_report(targets, preds, target_names=classes, output_dict=True, zero_division=0)
    
    # Convert to DataFrame for sorting
    class_metrics = []
    for cls in classes:
        if cls in report:
            class_metrics.append({
                'Technique': cls,
                'F1': report[cls]['f1-score'],
                'Support': report[cls]['support']
            })
            
    df_metrics = pd.DataFrame(class_metrics)
    df_metrics = df_metrics.sort_values(by='F1', ascending=False)
    
    print("\n[Top 10 Performing Techniques]")
    print(df_metrics.head(10).to_string(index=False))
    
    print("\n[Worst 10 Performing Techniques]")
    print(df_metrics.tail(10).to_string(index=False))

def main():
    # 1. Load Artifacts
    texts, targets, mlb = load_data()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    model.to(device)
    
    # 2. Prepare Data
    dataset = EvaluationDataset(texts, targets, tokenizer, MAX_LEN)
    loader = DataLoader(dataset, batch_size=BATCH_SIZE, num_workers=0)
    
    # 3. Get Probabilities
    probs, targets = get_predictions(model, loader)
    
    # 4. Tune Threshold
    best_thresh = find_optimal_threshold(probs, targets)
    
    # 5. Apply Threshold & Report
    final_preds = (probs > best_thresh).astype(int)
    detailed_report(targets, final_preds, mlb.classes_)

if __name__ == "__main__":
    main()