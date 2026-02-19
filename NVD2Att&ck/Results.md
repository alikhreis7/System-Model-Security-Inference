``` mermaid
flowchart TD
    %% --- Data Sources ---
    subgraph Sources ["Data Sources"]
        direction TB
        NVD_Feed[("NVD JSON Feeds<br>(2002-2026)")]
        KEV_List[("CISA KEV<br>(Gold Standard)")]
        MITRE_XML[("MITRE CWE & CAPEC<br>(XML Definitions)")]
    end

    %% --- Processing Logic ---
    subgraph Logic ["Matching Engine"]
        direction TB
        CVE_Item("CVE Item<br>(ID & Description)")
        
        %% Path 1: Gold Standard
        check_kev{"Match in KEV?"}
        label_gold["Label: Gold Standard<br>(Confirmed Exploited)"]
        
        %% Path 2: Transitive Mapping
        extract_cwe("Extract CWE-ID<br>(e.g., CWE-89)")
        map_cwe_capec("Map CWE → CAPEC<br>(via CWE XML)")
        map_capec_attack("Map CAPEC → ATT&CK<br>(via CAPEC XML)")
        label_silver["Label: Transitive<br>(Inferred Technique)"]
    end

    %% --- Final Output ---
    subgraph Result ["Training Data"]
        Final_Entry[("Labeled Sample<br>{Text, Labels, Source}")]
    end

    %% --- Connections ---
    NVD_Feed --> CVE_Item
    CVE_Item --> check_kev
    KEV_List --> check_kev
    
    %% Gold Path
    check_kev -- Yes --> label_gold
    
    %% Silver Path (The Transitive Chain)
    check_kev -- No / Augment --> extract_cwe
    CVE_Item --> extract_cwe
    extract_cwe -->|CWE-89| map_cwe_capec
    MITRE_XML -.-> map_cwe_capec
    map_cwe_capec -->|CAPEC-66| map_capec_attack
    MITRE_XML -.-> map_capec_attack
    map_capec_attack -->|T1190| label_silver

    %% Merging
    label_gold --> Final_Entry
    label_silver --> Final_Entry

    %% Styling
    classDef source fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    classDef logic fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;
    classDef result fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    
    class NVD_Feed,KEV_List,MITRE_XML source;
    class check_kev,extract_cwe,map_cwe_capec,map_capec_attack logic;
    class Final_Entry result;
```


# SecureBert+ on Full (techniques & sub-techniques)

## Classes 183
## Optimal Threshold found: 0.4
## New Best F1 Score: 0.7102
```
--- Detailed Metrics ---
Micro Precision: 0.7420
Micro Recall:    0.6811
Micro F1:        0.7102
Macro F1:        0.3672 (Avg across all classes)
Hamming Loss:    0.0255 (Lower is better)

--- Class Performance (Top 10 Best & Worst) ---

[Top 10 Performing Techniques]
Technique       F1  Support
T1574.009 0.874404    325.0
T1547.009 0.843564    272.0
T1574.007 0.812196   5581.0
T1562.003 0.806803   5274.0
T1574.006 0.803464   5305.0
T1542.002 0.799016   1577.0
    T1217 0.798387   1887.0
    T1556 0.797891   1577.0
    T1120 0.797629   1887.0
    T1592 0.797305   1888.0

[Worst 10 Performing Techniques]
Technique  F1  Support
T1598.003 0.0     29.0
    T1598 0.0     29.0
    T1600 0.0      3.0
    T1602 0.0     94.0
T1606.001 0.0     28.0
    T1606 0.0     93.0
    T1611 0.0     77.0
    T1614 0.0     45.0
    T1620 0.0     44.0
    T1647 0.0     11.0
```	
---

# SecureBert+ on Techniques only (techniques & collapsed sub-techniques)

## Classes 105
## Optimal Threshold found: 0.45
## New Best F1 Score: 0.7570
```
--- Detailed Metrics ---
Micro Precision: 0.7704
Micro Recall:    0.7441
Micro F1:        0.7570
Macro F1:        0.3832 (Avg across all classes)
Hamming Loss:    0.0315 (Lower is better)

--- Class Performance (Top 10 Best & Worst) ---

[Top 10 Performing Techniques]
Technique       F1  Support
    T1574 0.858222   8254.0
    T1027 0.837278   5521.0
    T1499 0.819731   1192.0
    T1211 0.813117   1573.0
    T1562 0.810039   6139.0
    T1124 0.804657   1873.0
    T1046 0.804033   1874.0
    T1069 0.803202   1873.0
    T1016 0.803101   1873.0
    T1595 0.802795   1873.0

[Worst 10 Performing Techniques]
Technique  F1  Support
    T1584 0.0    181.0
    T1566 0.0     32.0
    T1598 0.0     33.0
    T1600 0.0      3.0
    T1606 0.0    120.0
    T1602 0.0     85.0
    T1611 0.0     74.0
    T1614 0.0     42.0
    T1620 0.0     41.0
    T1647 0.0     12.0
```

