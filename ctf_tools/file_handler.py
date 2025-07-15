import os
from .static_analysis import extract_strings, run_binwalk
from .decoders import decode_base64, decode_hex, decode_rot13
from .exif_tools import extract_exif
from .pdf_tools import extract_pdf_content
import re
import string
from PIL import Image
import io

def is_printable_flag(flag):
    if '{' in flag and '}' in flag:
        content = flag[flag.find('{')+1:flag.rfind('}')]
        return all(c in string.printable and c not in '\r\n\t\x0b\x0c' for c in content)
    return False

def analyze_one_file(filepath):
    flag_regex = re.compile(r'([A-Za-z_]+\{.*?\})', re.IGNORECASE)
    file_result = {}
    flags_detected = []
    # Analyse PDF
    if filepath.lower().endswith('.pdf'):
        pdf_content = extract_pdf_content(filepath)
        file_result['pdf_text'] = pdf_content.get('text', '')
        file_result['pdf_images_count'] = len(pdf_content.get('images', []))
        for match in flag_regex.finditer(file_result['pdf_text']):
            if is_printable_flag(match.group(0)):
                flags_detected.append({'flag': match.group(0), 'method': 'pdf_text'})
        for idx, img_bytes in enumerate(pdf_content.get('images', [])):
            try:
                img = Image.open(io.BytesIO(img_bytes))
                exif = img.getexif()
                if exif:
                    for tag_id, value in exif.items():
                        val = str(value)
                        for match in flag_regex.finditer(val):
                            if is_printable_flag(match.group(0)):
                                flags_detected.append({'flag': match.group(0), 'method': 'pdf_image_exif'})
            except Exception:
                continue
    # Analyse statique classique
    strings_result = extract_strings(filepath)
    file_result['strings'] = strings_result
    file_result['binwalk'] = run_binwalk(filepath)
    if filepath.lower().endswith(('.jpg', '.jpeg', '.png')):
        exif = extract_exif(filepath)
        file_result['exif'] = exif
        if isinstance(exif, dict):
            for val in exif.values():
                for match in flag_regex.finditer(str(val)):
                    if is_printable_flag(match.group(0)):
                        flags_detected.append({'flag': match.group(0), 'method': 'exif'})
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
                        if is_printable_flag(match.group(0)):
                            flags_detected.append({'flag': match.group(0), 'method': label})
            for line in strings_result.splitlines():
                line = line.strip()
                if not line:
                    continue
                for label, val in [('base64', decode_base64(line)), ('hex', decode_hex(line)), ('rot13', decode_rot13(line))]:
                    if val:
                        for match in flag_regex.finditer(val):
                            if is_printable_flag(match.group(0)):
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
    return {filepath: file_result}

def process_directory(directory):
    results = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            results.update(analyze_one_file(filepath))
    return results

def process_file(filepath):
    return analyze_one_file(filepath)
