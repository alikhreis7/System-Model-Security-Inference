import xml.etree.ElementTree as ET
import json
import os
import re
from packaging import version # Required for semantic version comparison


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


def is_version_in_range(v_str, start_inc=None, end_inc=None, start_exc=None, end_exc=None):
    """Checks if a version string falls within NVD-defined ranges."""
    try:
        v = version.parse(v_str)
        if start_inc and v < version.parse(start_inc): return False
        if start_exc and v <= version.parse(start_exc): return False
        if end_inc and v > version.parse(end_inc): return False
        if end_exc and v >= version.parse(end_exc): return False
        return True
    except:
        return False # Fallback for non-standard version strings

def cpe_matches(target_cpe_str, cve_cpe_entry):
    """Compares target CPE against CVE criteria including range logic."""
    criteria = cve_cpe_entry.get('criteria', '')
    target_parts = target_cpe_str.split(':')
    crit_parts = criteria.split(':')
    
    if len(target_parts) < 5 or len(crit_parts) < 5:
        return False
        
    # Vendor and Product must match
    if target_parts[3] != crit_parts[3] or target_parts[4] != crit_parts[4]:
        return False

    target_v = target_parts[5]
    crit_v = crit_parts[5]

    # If criteria specifies a specific version, it must match
    if crit_v != '*' and crit_v != '-':
        if target_v != crit_v:
            return False
            
    # CHECK VERSION RANGES (The missing link for Spring Framework 5.3.18)
    if target_v != '*' and target_v != '-':
        range_params = {
            'start_inc': cve_cpe_entry.get('versionStartIncluding'),
            'start_exc': cve_cpe_entry.get('versionStartExcluding'),
            'end_inc': cve_cpe_entry.get('versionEndIncluding'),
            'end_exc': cve_cpe_entry.get('versionEndExcluding')
        }
        if any(range_params.values()):
            if not is_version_in_range(target_v, **range_params):
                return False
                
    return True

def perform_mapping(components, nvd_dir):
    """Maps components with CVSS score and reference extraction."""
    target_years = set(range(2020, 2027))
    results = { (c['name'] or c['id']): {'metadata': c, 'matched_cves': []} for c in components }
    
    nvd_files = [os.path.join(nvd_dir, f) for f in os.listdir(nvd_dir) 
                 if f.endswith('.json') and any(str(yr) in f for yr in target_years)]

    for nvd_file in sorted(nvd_files):
        with open(nvd_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id')
                
                # 1. Extract CVSS Score (Prioritize V3.1)
                metrics = cve.get('metrics', {})
                cvss_score = None
                for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if key in metrics:
                        cvss_score = metrics[key][0]['cvssData']['baseScore']
                        break
                
                # 2. Extract References
                references = [ref.get('url') for ref in cve.get('references', [])]
                desc = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), "")

                for key, val in results.items():
                    comp = val['metadata']
                    is_match = False
                    
                    if comp['cpe']:
                        for config in cve.get('configurations', []):
                            for node in config.get('nodes', []):
                                for cpe_entry in node.get('cpeMatch', []):
                                    if cpe_matches(comp['cpe'], cpe_entry):
                                        is_match = True
                                        break
                                if is_match: break
                            if is_match: break
                    
                    # Fallback text search
                    if not is_match and comp['product']:
                        if comp['product'].lower() in desc.lower():
                            if not comp['version'] or comp['version'] in desc:
                                is_match = True
                    
                    if is_match:
                        val['matched_cves'].append({
                            'cve_id': cve_id,
                            'cvss_score': cvss_score,
                            'description': desc,
                            'references': references
                        })
    return results

# Configuration
SYSML_PATH = './SOI/MedGateway_ReferenceArchitecture.sysml.xml'
NVD_DIR = './OSRs/NVD'

# Run
components = extract_sysml_components(SYSML_PATH)
final_mapping = perform_mapping(components, NVD_DIR)

with open('./SysML2CVE/cve_mapping_output.json', 'w') as f:
    json.dump(final_mapping, f, indent=2)

