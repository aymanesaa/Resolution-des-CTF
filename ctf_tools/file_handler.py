import os
from .static_analysis import extract_strings, run_binwalk
from .decoders import decode_base64, decode_hex, decode_rot13
import re

def process_directory(directory):
    results = {}
    flag_regex = re.compile(r'(CTF\{.*?\}|FLAG\{.*?\})', re.IGNORECASE)
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_result = {}
            
            # Analyse statique
            strings_result = extract_strings(filepath)
            file_result['strings'] = strings_result
            file_result['binwalk'] = run_binwalk(filepath)
            
            # Décodages (lecture du contenu brut)
            try:
                with open(filepath, 'rb') as f:
                    raw = f.read()
                    try:
                        text = raw.decode('utf-8', errors='ignore')
                    except:
                        text = ''
                    # Décodages sur le texte brut
                    b64 = decode_base64(text)
                    hx = decode_hex(text)
                    rot = decode_rot13(text)
                    file_result['base64'] = b64
                    file_result['hex'] = hx
                    file_result['rot13'] = rot
                    # Détection de flag dans tous les résultats
                    for label, val in [('strings', strings_result), ('base64', b64), ('hex', hx), ('rot13', rot)]:
                        if val:
                            match = flag_regex.search(val)
                            if match:
                                file_result['flag_detected'] = {'flag': match.group(0), 'method': label}
                                break
                    # Décodages sur chaque chaîne extraite par strings
                    for line in strings_result.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        for label, val in [('base64', decode_base64(line)), ('hex', decode_hex(line)), ('rot13', decode_rot13(line))]:
                            if val:
                                match = flag_regex.search(val)
                                if match:
                                    file_result['flag_detected'] = {'flag': match.group(0), 'method': label}
                                    break
                        if 'flag_detected' in file_result:
                            break
            except Exception as e:
                file_result['decode_error'] = str(e)
            
            results[filepath] = file_result
    return results