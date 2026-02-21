import xml.etree.ElementTree as ET
import json
import os
import re

def extract_sysml_components(sysml_path):
    """Extracts components, CPEs, and product names from SysML XML."""
    tree = ET.parse(sysml_path)
    root = tree.getroot()
    
    # Namespaces commonly used in SysML/UML exports
    ns = {
        'xmi': 'http://www.omg.org/spec/XMI/20131001',
        'uml': 'http://www.omg.org/spec/UML/20131001',
        'sysml': 'http://www.omg.org/spec/SysML/20131001' # Adjusted based on file header
    }

    components = []
    # Find all blocks/classes in the model
    for element in root.findall(".//packagedElement[@xmi:type='sysml:Block']", ns) + \
                   root.findall(".//packagedElement[@xmi:type='uml:Class']", ns):
        
        comp_data = {
            'id': element.get('{http://www.omg.org/spec/XMI/20131001}id'),
            'name': element.get('name'),
            'cpe': None,
            'version': None
        }

        # Look for CPE or Version in comments or attributes
        for comment in element.findall("ownedComment"):
            body = comment.get('body', '')
            cpe_match = re.search(r'cpe:2\.3:[a-z]:[^:]+:[^:]+:[^:]+', body)
            if cpe_match:
                comp_data['cpe'] = cpe_match.group(0)
            
            version_match = re.search(r'v(?:ersion)?\s?(\d+\.\d+(?:\.\d+)?)', body)
            if version_match:
                comp_data['version'] = version_match.group(1)

        components.append(comp_data)
    return components

def map_to_cves(components, nvd_folder):
    """Maps extracted components to CVEs using CPE or Name/Version search."""
    mapping_results = {}

    for comp in components:
        comp_id = comp['name'] or comp['id']
        mapping_results[comp_id] = {
            'metadata': comp,
            'matched_cves': []
        }

        # Iterate through NVD files (2020-2026)
        for filename in os.listdir(nvd_folder):
            if filename.endswith(".json"):
                with open(os.path.join(nvd_folder, filename), 'r') as f:
                    nvd_data = json.load(f)
                    
                    for vuln in nvd_data.get('vulnerabilities', []):
                        cve = vuln.get('cve', {})
                        cve_id = cve.get('id')
                        description = cve.get('descriptions', [{}])[0].get('value', '')
                        
                        match_found = False
                        
                        # 1. Match by CPE identifier
                        if comp['cpe']:
                            configs = cve.get('configurations', [])
                            for config in configs:
                                for node in config.get('nodes', []):
                                    for match in node.get('cpeMatch', []):
                                        if comp['cpe'] in match.get('criteria', ''):
                                            match_found = True
                        
                        # 2. Fallback: Search name and version in description
                        if not match_found and comp['name']:
                            search_term = comp['name'].lower()
                            if search_term in description.lower():
                                if not comp['version'] or (comp['version'] in description):
                                    match_found = True

                        if match_found:
                            mapping_results[comp_id]['matched_cves'].append({
                                'cve_id': cve_id,
                                'description': description
                            })

    return mapping_results

# Execution
# Assume 'SOI' contains SysML and 'OSRs/NVD' contains JSONs
sysml_file = './SOI/MedGateway_ReferenceArchitecture.sysml.xml'
nvd_dir = './OSRs/NVD'

extracted = extract_sysml_components(sysml_file)
final_mapping = map_to_cves(extracted, nvd_dir)

# Output for Step 3 (NLP-ready format)
with open('cve_mapping_output.json', 'w') as out:
    json.dump(final_mapping, out, indent=2)

print(f"Mapped {len(final_mapping)} components to CVEs.")