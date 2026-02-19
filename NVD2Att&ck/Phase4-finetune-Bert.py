import os
import torch
import numpy as np
import pandas as pd
import pickle
import logging
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from torch.utils.tensorboard import SummaryWriter
from transformers import AutoTokenizer, AutoModelForSequenceClassification, get_linear_schedule_with_warmup
from sklearn.metrics import f1_score

# --- Configuration ---
DATA_DIR = "./processed_data_parent"
MODEL_DIR = "./models/transformer_parent" # New directory for the better model
LOG_DIR = "./runs/transformer_experiment_parent"
MODEL_NAME = "distilroberta-base"            # The Cybersecurity Specialist
MAX_LEN = 256
BATCH_SIZE = 64   # Reduced to 8 because SecureBERT is larger than DistilRoBERTa
EPOCHS = 4
LEARNING_RATE = 2e-5
LOG_INTERVAL = 50  # Print status every 50 batches

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
# Setup TensorBoard
writer = SummaryWriter(LOG_DIR)

# Check Device
if torch.cuda.is_available():
    device = torch.device('cuda')
    logging.info(f"Using GPU: {torch.cuda.get_device_name(0)}")
else:
    device = torch.device('cpu')
    logging.warning("GPU not detected! Training will be slow.")

class CVEDataset(Dataset):
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

        # SecureBERT Tokenization
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
            'text': text,
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.FloatTensor(label)
        }

def load_data():
    logging.info("Loading Data...")
    train_text = pd.read_csv(os.path.join(DATA_DIR, "train_text.csv"))['text'].fillna("").values
    test_text = pd.read_csv(os.path.join(DATA_DIR, "test_text.csv"))['text'].fillna("").values
    y_train = np.load(os.path.join(DATA_DIR, "y_train.npz"))['arr_0']
    y_test = np.load(os.path.join(DATA_DIR, "y_test.npz"))['arr_0']
    
    with open(os.path.join(DATA_DIR, "mlb.pkl"), "rb") as f:
        mlb = pickle.load(f)
        
    return train_text, test_text, y_train, y_test, len(mlb.classes_)

def train_epoch(model, data_loader, loss_fn, optimizer, scheduler, device, n_examples):
    model = model.train()
    losses = []
    
    total_steps = len(data_loader)
    for i, d in enumerate(data_loader):
        input_ids = d["input_ids"].to(device)
        attention_mask = d["attention_mask"].to(device)
        targets = d["labels"].to(device)

        outputs = model(
            input_ids=input_ids,
            attention_mask=attention_mask
        )
        
        logits = outputs.logits
        loss = loss_fn(logits, targets)

        losses.append(loss.item())
        loss.backward()
        
        # Gradient Clipping
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        
        optimizer.step()
        scheduler.step()
        optimizer.zero_grad()

        # Real-time Logging
        if (i + 1) % LOG_INTERVAL == 0:
            avg_loss = np.mean(losses[-LOG_INTERVAL:])
            global_step = (n_examples * total_steps) + i
            
            # Print to Console
            logging.info(f"Epoch [{n_examples+1}/{EPOCHS}] Step [{i+1}/{total_steps}] Loss: {avg_loss:.4f}")
            
            # Log to TensorBoard
            writer.add_scalar('Training Loss', avg_loss, global_step)

    return np.mean(losses)

def eval_model(model, data_loader, loss_fn, device, n_examples):
    model = model.eval()
    losses = []
    all_preds = []
    all_targets = []

    with torch.no_grad():
        for d in data_loader:
            input_ids = d["input_ids"].to(device)
            attention_mask = d["attention_mask"].to(device)
            targets = d["labels"].to(device)

            outputs = model(
                input_ids=input_ids,
                attention_mask=attention_mask
            )
            
            loss = loss_fn(outputs.logits, targets)
            losses.append(loss.item())
            
            probs = torch.sigmoid(outputs.logits).cpu().numpy()
            targets = targets.cpu().numpy()
            
            all_preds.extend(probs)
            all_targets.extend(targets)

    return np.mean(losses), np.array(all_preds), np.array(all_targets)

def main():
    X_train, X_test, y_train, y_test, n_classes = load_data()
    
    logging.info(f"Loading Tokenizer ({MODEL_NAME})...")
    # SecureBERT uses the RoBERTa tokenizer structure
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    
    # SAFETY: Ensure pad token is set
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        
    train_ds = CVEDataset(X_train, y_train, tokenizer, MAX_LEN)
    test_ds = CVEDataset(X_test, y_test, tokenizer, MAX_LEN)
    
    # num_workers=0 is safer on Windows
    train_loader = DataLoader(train_ds, batch_size=BATCH_SIZE, shuffle=True, num_workers=0)
    test_loader = DataLoader(test_ds, batch_size=BATCH_SIZE, num_workers=0)
    
    logging.info(f"Initializing Model (Classes: {n_classes})...")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, 
        num_labels=n_classes,
        problem_type="multi_label_classification"
    )
    model = model.to(device)
    
    optimizer = AdamW(model.parameters(), lr=LEARNING_RATE)
    
    total_steps = len(train_loader) * EPOCHS
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=0,
        num_training_steps=total_steps
    )
    
    loss_fn = torch.nn.BCEWithLogitsLoss()
    
    logging.info("Starting Training with SecureBERT...")
    best_f1 = 0
    
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)

    for epoch in range(EPOCHS):
        logging.info(f"Epoch {epoch + 1}/{EPOCHS}")
        
        train_loss = train_epoch(
            model, train_loader, loss_fn, optimizer, scheduler, device, len(X_train)
        )
        
        logging.info(f"Train loss: {train_loss:.4f}")
        
        val_loss, preds, targets = eval_model(
            model, test_loader, loss_fn, device, len(X_test)
        )
        
        preds_binary = (preds > 0.5).astype(int)
        val_f1 = f1_score(targets, preds_binary, average='micro')
        
        logging.info(f"Val loss: {val_loss:.4f} | Micro F1: {val_f1:.4f}")
        writer.add_scalar('Validation Loss', val_loss, epoch)
        writer.add_scalar('Validation F1', val_f1, epoch)     

        if val_f1 > best_f1:
            logging.info(f"New Best F1! ({val_f1:.4f} > {best_f1:.4f}). Saving model...")            
            model.save_pretrained(MODEL_DIR)
            tokenizer.save_pretrained(MODEL_DIR)
            best_f1 = val_f1

    logging.info(f"Training Complete. Best F1: {best_f1}")
    writer.close()

if __name__ == "__main__":
    main()