import base64
import codecs
import re

def decode_base64(data):
    # Nettoie le texte - garde seulement les caractères base64 valides
    cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', data.strip())
    
    # Vérifie la longueur (base64 doit être multiple de 4 avec padding)
    if len(cleaned) == 0 or len(cleaned) % 4 != 0:
        return ''
    
    try:
        return base64.b64decode(cleaned).decode('utf-8', errors='ignore')
    except Exception:
        return ''

def decode_hex(data):
    # Vérifie si le texte ressemble à de l'hexadécimal
    if not re.fullmatch(r'[A-Fa-f0-9\s]+', data.strip()):
        return ''
    try:
        return bytes.fromhex(data).decode('utf-8', errors='ignore')
    except Exception:
        return ''

def decode_rot13(data):
    try:
        return codecs.decode(data, 'rot_13')
    except Exception:
        return '' 