import xml.etree.ElementTree as ET
import json
import os
import re

def extract_sysml_components(sysml_path):
    """Parses SysML XML to extract components from attributes and comments."""
    if not os.path.exists(sysml_path):
        print(f"Error: {sysml_path} not found.")
        return []
        
    tree = ET.parse(sysml_path)
    root = tree.getroot()
    ns = {
        'xmi': 'http://www.omg.org/spec/XMI/20131001',
        'uml': 'http://www.omg.org/spec/UML/20131001',
        'sysml': 'http://www.omg.org/spec/SysML/20131001'
    }

    components = []
    elements = root.findall(".//packagedElement[@xmi:type='sysml:Block']", ns) + \
               root.findall(".//packagedElement[@xmi:type='uml:Class']", ns)
    
    for element in elements:
        comp_data = {
            'id': element.get('{http://www.omg.org/spec/XMI/20131001}id'),
            'name': element.get('name'),
            'product': None, 'version': None, 'cpe': None
        }
        
        # 1. Primary: Extract from ownedAttribute (Targeting your specific XML structure)
        for attr in element.findall("ownedAttribute"):
            name_attr = attr.get('name', '').lower()
            val = attr.get('default')
            if not val: continue
            
            if 'cpe' in name_attr: comp_data['cpe'] = val
            elif 'product' in name_attr: comp_data['product'] = val
            elif 'version' in name_attr: comp_data['version'] = val

        # 2. Secondary: Fallback to ownedComment via Regex
        for comment in element.findall("ownedComment"):
            body = comment.get('body', '')
            if not body: continue
            if not comp_data['cpe']:
                cpe_match = re.search(r'cpe:2\.3:[a-z]:[^:]+:[^:]+:[^:]+', body)
                if cpe_match: comp_data['cpe'] = cpe_match.group(0)
            if not comp_data['version']:
                version_match = re.search(r'v(?:ersion)?\s?(\d+\.\d+(?:\.\d+)?)', body)
                if version_match: comp_data['version'] = version_match.group(1)

        components.append(comp_data)
    return components

def perform_mapping(components, nvd_dir):
    """Filters NVD files (2020-2026) and maps them to extracted components."""
    results = { (c['name'] or c['id']): {'metadata': c, 'matched_cves': []} for c in components }
    
    # Filter files for years 2020-2026
    target_years = set(range(2020, 2027))
    nvd_files = []
    for f in os.listdir(nvd_dir):
        if f.endswith('.json') and any(str(yr) in f for yr in target_years):
            nvd_files.append(os.path.join(nvd_dir, f))

    for nvd_file in sorted(nvd_files):
        print(f"Processing {os.path.basename(nvd_file)}...")
        with open(nvd_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id')
                desc = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), "")
                
                # Gather all CPEs for this CVE
                cve_cpes = []
                for config in cve.get('configurations', []):
                    for node in config.get('nodes', []):
                        for m in node.get('cpeMatch', []):
                            cve_cpes.append(m.get('criteria', ''))

                for key, val in results.items():
                    comp = val['metadata']
                    match = False
                    # Match by CPE
                    if comp['cpe'] and any(comp['cpe'] in target for target in cve_cpes):
                        match = True
                    # Match by Name + Version in description
                    elif not match:
                        p_name = comp['product'] if comp['product'] else comp['name']
                        if p_name and p_name.lower() in desc.lower():
                            if not comp['version'] or comp['version'] in desc:
                                match = True
                    
                    if match:
                        val['matched_cves'].append({'cve_id': cve_id, 'description': desc})
    return results

# Configuration
SYSML_PATH = './SOI/MedGateway_ReferenceArchitecture.sysml.xml'
NVD_DIR = './OSRs/NVD'

# Run
components = extract_sysml_components(SYSML_PATH)
final_mapping = perform_mapping(components, NVD_DIR)

with open('./SysML2CVE/cve_mapping_output.json', 'w') as f:
    json.dump(final_mapping, f, indent=2)

