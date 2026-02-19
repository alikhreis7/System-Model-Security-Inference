import os
import json
import logging
import zipfile
import io
import requests
import pandas as pd
import xml.etree.ElementTree as ET
import time
from datetime import datetime
from collections import Counter

# --- Configuration ---
# Directories
BASE_DIR = "./OSRs"
NVD_DIR = os.path.join(BASE_DIR, "NVD")
MAPPING_DIR = os.path.join(BASE_DIR, "MAPPINGS")
LOG_FILE = "phase1_pipeline.log"
OUTPUT_FILE = "phase1_dataset_final.csv"

# URLs
# NVD 2.0 Bulk Feeds (Official NIST URL pattern)
NVD_URL_PATTERN = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.zip"
# CAPEC & CWE (XML is more reliable for transitive mapping)
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
# CISA KEV (Gold Standard Labels)
KEV_URL = "https://center-for-threat-informed-defense.github.io/mappings-explorer/data/kev/attack-15.1/kev-02.13.2025/enterprise/kev-02.13.2025_attack-15.1-enterprise_json.json"

# Years to fetch from NVD
START_YEAR = 2002
END_YEAR = 2026

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode='w'), # Overwrite log each run
        logging.StreamHandler()
    ]
)

class CVEToATTACKPipeline:
    def __init__(self):
        self.capec_to_attack = {}  # CAPEC-ID -> Set(T-Codes)
        self.cwe_to_attack = {}    # CWE-ID -> Set(T-Codes)
        self.gold_labels = {}      # CVE-ID -> Set(T-Codes)
        self._ensure_directories()

    def _ensure_directories(self):
        for d in [NVD_DIR, MAPPING_DIR]:
            if not os.path.exists(d):
                os.makedirs(d)
                logging.info(f"Created directory: {d}")

    def download_nvd_data(self):
        """Downloads and extracts NVD JSON feeds (2002-2026)."""
        logging.info(f"--- [1] Checking NVD Data ({START_YEAR}-{END_YEAR}) ---")
        
        for year in range(START_YEAR, END_YEAR + 1):
            filename = f"nvdcve-2.0-{year}.json"
            filepath = os.path.join(NVD_DIR, filename)
            
            if os.path.exists(filepath):
                # Check if file is not empty/corrupt? For now, just exist check.
                continue

            url = NVD_URL_PATTERN.format(year=year)
            logging.info(f"Downloading NVD feed for {year}...")
            
            try:
                r = requests.get(url, stream=True)
                if r.status_code == 200:
                    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                        z.extractall(NVD_DIR)
                    logging.info(f"  -> Extracted {filename}")
                else:
                    logging.warning(f"  -> Failed to download {year} (Status {r.status_code})")
            except Exception as e:
                logging.error(f"  -> Error downloading {year}: {e}")
            
            time.sleep(1) # Be nice to NIST servers

    def download_mappings(self):
        """Downloads CAPEC (XML), CWE (Zip->XML), and KEV (JSON)."""
        logging.info("--- [2] Downloading Mapping Standards ---")
        
        # 1. CAPEC
        capec_path = os.path.join(MAPPING_DIR, "capec_latest.xml")
        if not os.path.exists(capec_path):
            logging.info(f"Downloading CAPEC from {CAPEC_URL}...")
            try:
                r = requests.get(CAPEC_URL)
                with open(capec_path, 'wb') as f:
                    f.write(r.content)
            except Exception as e:
                logging.error(f"Failed to download CAPEC: {e}")

        # 2. CWE (Robust Zip Extraction Logic)
        # We assume if cwec_latest.xml exists, we are good. If not, try download.
        final_cwe_path = os.path.join(MAPPING_DIR, "cwec_latest.xml")
        if not os.path.exists(final_cwe_path):
            logging.info(f"Downloading CWE from {CWE_URL}...")
            try:
                r = requests.get(CWE_URL)
                with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                    # Search for the .xml file inside the zip (name changes by version)
                    xml_files = [f for f in z.namelist() if f.endswith('.xml')]
                    if not xml_files:
                        logging.error("No XML found inside CWE zip!")
                    else:
                        target_file = xml_files[0]
                        logging.info(f"Extracting {target_file} from CWE Zip...")
                        z.extract(target_file, MAPPING_DIR)
                        
                        # Rename to standard name
                        extracted_path = os.path.join(MAPPING_DIR, target_file)
                        if os.path.exists(final_cwe_path):
                            os.remove(final_cwe_path)
                        os.rename(extracted_path, final_cwe_path)
            except Exception as e:
                logging.error(f"Failed to download/extract CWE: {e}")

        # 3. KEV (Gold Standard)
        kev_path = os.path.join(MAPPING_DIR, "kev_mapping.json")
        if not os.path.exists(kev_path):
            logging.info(f"Downloading KEV from {KEV_URL}...")
            try:
                r = requests.get(KEV_URL)
                with open(kev_path, 'wb') as f:
                    f.write(r.content)
            except Exception as e:
                logging.error(f"Failed to download KEV: {e}")

    def parse_mappings(self):
        """Parses the downloaded files to build the dictionaries (Namespace Agnostic)."""
        logging.info("--- [3] Parsing Standards (XML/JSON) ---")
        
        # Helper to strip namespaces like {http://capec.mitre.org...}
        strip_ns = lambda t: t.split('}', 1)[1] if '}' in t else t
        
        # 1. CAPEC Parsing
        capec_path = os.path.join(MAPPING_DIR, "capec_latest.xml")
        try:
            tree = ET.parse(capec_path)
            root = tree.getroot()
            
            for elem in root.iter():
                if strip_ns(elem.tag) == "Attack_Pattern":
                    capec_id = elem.get("ID")
                    if not capec_id: continue
                    full_capec = f"CAPEC-{capec_id}"
                    
                    # Look for Taxonomy_Mappings -> ATTACK
                    for child in elem.iter():
                        if strip_ns(child.tag) == "Taxonomy_Mapping":
                            if child.get("Taxonomy_Name") == "ATTACK":
                                for sub in child:
                                    if strip_ns(sub.tag) == "Entry_ID":
                                        tid = sub.text.strip()
                                        if not tid.startswith("T"): tid = "T" + tid
                                        
                                        if full_capec not in self.capec_to_attack:
                                            self.capec_to_attack[full_capec] = set()
                                        self.capec_to_attack[full_capec].add(tid)
            logging.info(f"Mapped {len(self.capec_to_attack)} CAPECs to ATT&CK.")
        except Exception as e:
            logging.error(f"CAPEC Parse Error: {e}")

        # 2. CWE Parsing
        cwe_path = os.path.join(MAPPING_DIR, "cwec_latest.xml")
        try:
            tree = ET.parse(cwe_path)
            root = tree.getroot()
            for elem in root.iter():
                if strip_ns(elem.tag) == "Weakness":
                    cwe_id = elem.get("ID")
                    if not cwe_id: continue
                    full_cwe = f"CWE-{cwe_id}"
                    
                    for child in elem.iter():
                        if strip_ns(child.tag) == "Related_Attack_Pattern":
                            ref = child.get("CAPEC_ID")
                            if ref:
                                full_ref = f"CAPEC-{ref}"
                                if full_ref in self.capec_to_attack:
                                    if full_cwe not in self.cwe_to_attack:
                                        self.cwe_to_attack[full_cwe] = set()
                                    self.cwe_to_attack[full_cwe].update(self.capec_to_attack[full_ref])
            logging.info(f"Mapped {len(self.cwe_to_attack)} CWEs to ATT&CK.")
        except Exception as e:
            logging.error(f"CWE Parse Error: {e}")

        # 3. KEV Parsing
        kev_path = os.path.join(MAPPING_DIR, "kev_mapping.json")
        try:
            with open(kev_path, 'r') as f:
                data = json.load(f)
            for obj in data.get('mapping_objects', []):
                cve = obj.get('capability_id')
                tech = obj.get('attack_object_id')
                if cve and tech and cve.startswith("CVE-"):
                    if cve not in self.gold_labels:
                        self.gold_labels[cve] = set()
                    self.gold_labels[cve].add(tech)
            logging.info(f"Loaded {len(self.gold_labels)} Gold KEV Labels.")
        except Exception as e:
            logging.error(f"KEV Parse Error: {e}")

    def generate_dataset(self):
        """Scans NVD files and applies the maps."""
        logging.info("--- [4] Building Final Dataset ---")
        
        files = [f for f in os.listdir(NVD_DIR) if f.endswith('.json')]
        logging.info(f"Scanning {len(files)} NVD files...")
        
        dataset = []
        
        for file in files:
            path = os.path.join(NVD_DIR, file)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for item in data.get('vulnerabilities', []):
                    cve_item = item.get('cve', {})
                    cve_id = cve_item.get('id')
                    
                    # Get Text
                    desc = "N/A"
                    for d in cve_item.get('descriptions', []):
                        if d.get('lang') == 'en':
                            desc = d.get('value')
                            break
                    if desc == "N/A": continue
                    
                    labels = set()
                    sources = []

                    # A. Gold Labels
                    if cve_id in self.gold_labels:
                        labels.update(self.gold_labels[cve_id])
                        sources.append("gold")

                    # B. Transitive Labels (CWE)
                    cwe_list = []
                    for w in cve_item.get('weaknesses', []):
                        for d in w.get('description', []):
                            val = d.get('value')
                            if val.startswith("CWE-"):
                                cwe_list.append(val)
                    
                    for cwe in cwe_list:
                        if cwe in self.cwe_to_attack:
                            labels.update(self.cwe_to_attack[cwe])
                            if "transitive" not in sources:
                                sources.append("transitive")

                    if labels:
                        dataset.append({
                            'cve_id': cve_id,
                            'text': desc,
                            'labels': list(labels),
                            'source': "+".join(sources)
                        })

            except Exception as e:
                logging.warning(f"Skipping file {file}: {e}")

        # Save
        df = pd.DataFrame(dataset)
        df.to_csv(OUTPUT_FILE, index=False)
        logging.info(f"Dataset saved to {OUTPUT_FILE}")
        return df

    def validate_output(self, df):
        """Prints statistical validation of the dataset."""
        logging.info("--- [5] Validation & Stats ---")
        
        report = []
        report.append("\n" + "="*30)
        report.append("DATASET VALIDATION REPORT")
        report.append("="*30)
        report.append(f"Total Samples: {len(df)}")
        
        # 1. Source Distribution
        report.append("\n[Source Distribution]")
        report.append(str(df['source'].value_counts()))
        
        # 2. Label Stats
        all_labels = []
        for row in df['labels']:
            try:
                # If pandas loaded it as a string representation of a list
                lbls = eval(row) if isinstance(row, str) else row
                all_labels.extend(lbls)
            except:
                pass
                
        report.append(f"\n[Label Stats]")
        report.append(f"Unique Techniques Found: {len(set(all_labels))}")
        report.append(f"Total Assignments: {len(all_labels)}")
        
        # 3. Top 5 Techniques
        report.append("\n[Top 5 Most Common Techniques]")
        counts = Counter(all_labels)
        for tech, count in counts.most_common(5):
            report.append(f"  {tech}: {count} samples")

        report.append("="*30 + "\n")
        
        # Print to console and log
        final_report = "\n".join(report)
        print(final_report)
        logging.info(final_report)

if __name__ == "__main__":
    pipeline = CVEToATTACKPipeline()
    pipeline.download_nvd_data()
    pipeline.download_mappings()
    pipeline.parse_mappings()
    df = pipeline.generate_dataset()
    pipeline.validate_output(df)