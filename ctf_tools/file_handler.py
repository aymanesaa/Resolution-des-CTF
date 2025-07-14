import os
from .static_analysis import extract_strings, run_binwalk
from .decoders import decode_base64, decode_hex, decode_rot13
from .exif_tools import extract_exif
from .pdf_tools import extract_pdf_content
import re

def process_directory(directory):
    results = {}
    flag_regex = re.compile(r'([A-Za-z_]+\{.*?\})', re.IGNORECASE)
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            file_result = {}
            flags_detected = []
            # Analyse PDF
            if file.lower().endswith('.pdf'):
                pdf_content = extract_pdf_content(filepath)
                file_result['pdf_text'] = pdf_content.get('text', '')
                file_result['pdf_images'] = pdf_content.get('images', [])
                # Détection de flag dans le texte PDF
                for match in flag_regex.finditer(file_result['pdf_text']):
                    flags_detected.append({'flag': match.group(0), 'method': 'pdf_text'})
                # Analyse EXIF sur chaque image extraite
                for img_path in file_result['pdf_images']:
                    exif = extract_exif(img_path)
                    if exif:
                        if 'pdf_images_exif' not in file_result:
                            file_result['pdf_images_exif'] = {}
                        file_result['pdf_images_exif'][img_path] = exif
                        if isinstance(exif, dict):
                            for val in exif.values():
                                for match in flag_regex.finditer(str(val)):
                                    flags_detected.append({'flag': match.group(0), 'method': 'pdf_image_exif'})
            # Analyse statique classique
            strings_result = extract_strings(filepath)
            file_result['strings'] = strings_result
            file_result['binwalk'] = run_binwalk(filepath)
            # Extraction EXIF si image
            if file.lower().endswith(('.jpg', '.jpeg', '.png')):
                exif = extract_exif(filepath)
                file_result['exif'] = exif
                if isinstance(exif, dict):
                    for val in exif.values():
                        for match in flag_regex.finditer(str(val)):
                            flags_detected.append({'flag': match.group(0), 'method': 'exif'})
            # Décodages (lecture du contenu brut)
            try:
                with open(filepath, 'rb') as f:
                    raw = f.read()
                    try:
                        text = raw.decode('utf-8', errors='ignore')
                    except:
                        text = ''
                    b64 = decode_base64(text)
                    hx = decode_hex(text)
                    rot = decode_rot13(text)
                    file_result['base64'] = b64
                    file_result['hex'] = hx
                    file_result['rot13'] = rot
                    for label, val in [('strings', strings_result), ('base64', b64), ('hex', hx), ('rot13', rot)]:
                        if val:
                            for match in flag_regex.finditer(val):
                                flags_detected.append({'flag': match.group(0), 'method': label})
                    for line in strings_result.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        for label, val in [('base64', decode_base64(line)), ('hex', decode_hex(line)), ('rot13', decode_rot13(line))]:
                            if val:
                                for match in flag_regex.finditer(val):
                                    flags_detected.append({'flag': match.group(0), 'method': label})
            except Exception as e:
                file_result['decode_error'] = str(e)
            if flags_detected:
                file_result['flags_detected'] = flags_detected
            # Tronquer strings et rot13 à 50 caractères pour le rapport
            max_len = 50
            if 'strings' in file_result and isinstance(file_result['strings'], str) and len(file_result['strings']) > max_len:
                file_result['strings_excerpt'] = file_result['strings'][:max_len] + '...'
                del file_result['strings']
            if 'rot13' in file_result and isinstance(file_result['rot13'], str) and len(file_result['rot13']) > max_len:
                file_result['rot13_excerpt'] = file_result['rot13'][:max_len] + '...'
                del file_result['rot13']
            results[filepath] = file_result
    return results
