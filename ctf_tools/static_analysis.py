import subprocess
import string

def extract_strings(filepath):
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        # Supprime les caractères nuls (utile pour UTF-16 LE/BE)
        data = data.replace(b'\x00', b'')
        result = ''
        current = ''
        min_length = 4  # comme la commande 'strings'
        for b in data:
            c = chr(b)
            if c in string.printable and c not in '\r\x0b\x0c':
                current += c
            else:
                if len(current) >= min_length:
                    result += current + '\n'
                current = ''
        if len(current) >= min_length:
            result += current + '\n'
        return result
    except Exception as e:
        return f"Erreur strings: {e}"

def run_binwalk(filepath):
    try:
        result = subprocess.run(['binwalk', filepath], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Erreur binwalk: {e}" 