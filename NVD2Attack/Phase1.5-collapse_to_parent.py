import pandas as pd
import ast
import re

# --- Configuration ---
INPUT_FILE = "phase1_dataset_final.csv"
OUTPUT_FILE = "phase1_dataset_parent_only.csv"

def convert_to_parent(label_list):
    """
    Input:  ['T1059.001', 'T1059.006', 'T1003']
    Output: ['T1059', 'T1003']
    """
    if isinstance(label_list, str):
        label_list = ast.literal_eval(label_list)
        
    parent_labels = set()
    for label in label_list:
        # Regex to capture just the Txxxx part, ignoring .yyy
        # Matches T followed by digits, stops at dot or end
        match = re.match(r"(T\d+)", label)
        if match:
            parent_labels.add(match.group(1))
            
    return list(parent_labels)

def main():
    print(f"[*] Loading {INPUT_FILE}...")
    df = pd.read_csv(INPUT_FILE)
    
    # Apply transformation
    print("[*] Merging Sub-Techniques -> Parent Techniques...")
    df['labels'] = df['labels'].apply(convert_to_parent)
    
    # Remove rows that became empty (rare, but possible if a label was malformed)
    df = df[df['labels'].map(len) > 0]
    
    # Save
    print(f"[*] Saving to {OUTPUT_FILE}...")
    df.to_csv(OUTPUT_FILE, index=False)
    
    # Stats
    all_labels = [lbl for row in df['labels'] for lbl in row]
    unique_parents = len(set(all_labels))
    print(f"\n[SUCCESS]")
    print(f"New Class Count: {unique_parents} Parent Techniques")
    print(f"Total Samples:   {len(df)}")
    print("You can now re-run Phase 2 with this new file.")

if __name__ == "__main__":
    main()