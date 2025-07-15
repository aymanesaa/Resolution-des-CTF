import argparse
import os
from .file_handler import process_directory
from .report import save_report
from .decoders import decode_base64, decode_hex, decode_rot13
from .static_analysis import extract_strings, run_binwalk
import datetime
import string

def main():
    parser = argparse.ArgumentParser(description="CTF Automation Tool")
    parser.add_argument('--file', help='Fichier à traiter')
    parser.add_argument('--dir', help='Dossier à traiter')
    parser.add_argument('--decode', choices=['base64', 'hex', 'rot13'], help='Type de décodage')
    parser.add_argument('--analyze', choices=['strings', 'binwalk'], help='Type d\'analyse statique')
    parser.add_argument('--report', action='store_true', help='Générer un rapport')
    args = parser.parse_args()

    results = {}
    
    if args.file:
        from .file_handler import process_file
        results = process_file(args.file)
        res = results.get(args.file)
        if res:
            print(f"\nFichier : {args.file}")
            for key, value in res.items():
                print(f"  {key}: {value}")
        else:
            print("Aucun résultat pour ce fichier.")
                
        if args.decode:
            try:
                # Lecture intelligente du fichier
                with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                    data = f.read().strip()
                    print(f"avant dec: {data}")
                if args.decode == 'base64':
                    result = decode_base64(data)
                    print(f"Décodage Base64 : {result}")
                elif args.decode == 'hex':
                    result = decode_hex(data)
                    print(f"Décodage Hex : {result}")
                elif args.decode == 'rot13':
                    result = decode_rot13(data)
                    print(f"Décodage ROT13 : {result}")
            except Exception as e:
                print(f"Erreur lors du décodage : {e}")
                
        if args.analyze:
            try:
                if args.analyze == 'strings':
                    result = extract_strings(args.file)
                    print(f"Strings extraites :\n{result}")
                elif args.analyze == 'binwalk':
                    result = run_binwalk(args.file)
                    print(f"Analyse Binwalk :\n{result}")
            except Exception as e:
                print(f"Erreur lors de l'analyse : {e}")
                
    elif args.dir:
        print(f"Traitement du dossier : {args.dir}")
        results = process_directory(args.dir)
        
        # Affichage concis et filtré des résultats
        def is_printable(s):
            return all(c in string.printable for c in s)
        for filepath, res in results.items():
            print(f'\nFichier : {filepath}')
            # Affiche strings seulement si très court et imprimable
            if 'strings' in res and res['strings'] and len(res['strings']) <= 60 and is_printable(res['strings']):
                print(f'  strings: {res["strings"]}')
            # Affiche les décodages non vides, courts et imprimables
            for key in ['base64', 'hex', 'rot13']:
                if key in res and res[key] and len(res[key]) <= 60 and is_printable(res[key]):
                    print(f'  {key}: {res[key]}')
            # Affiche le flag_detected s'il existe
            if 'flag_detected' in res and res['flag_detected']:
                print(f'  flag_detected: {res["flag_detected"]}')
            
            # Affichage des erreurs
            if res.get('decode_error'):
                print(f"Erreur: {res['decode_error']}")
            if res.get('note'):
                print(f"Note: {res['note']}")
    
    if args.report:
        if not results:
            print('Aucun résultat trouvé, mais un rapport vide va être généré.')
        
        # Création du dossier rapports s'il n'existe pas
        os.makedirs('rapports', exist_ok=True)
        
        # Génère un nom de fichier unique avec timestamp
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = os.path.join('rapports', f'report_{timestamp}.json')
        save_report(results, filename=report_filename)
        print(f'Rapport généré : {report_filename}')

if __name__ == "__main__":
    main()