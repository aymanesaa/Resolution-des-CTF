from PyPDF2 import PdfReader

try:
    from PIL import Image
    import io
except ImportError:
    Image = None
    io = None

def extract_pdf_content(filepath):
    text = ''
    images = []
    try:
        reader = PdfReader(filepath)
        # Extraction du texte
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + '\n'
        # Extraction des images (en mémoire)
        for page_num, page in enumerate(reader.pages):
            if '/XObject' in page.get('/Resources', {}):
                xObject = page['/Resources']['/XObject'].get_object()
                for obj in xObject:
                    xobj = xObject[obj]
                    if xobj['/Subtype'] == '/Image':
                        img_data = xobj.get_data()
                        images.append(img_data)  # Ajoute les bytes de l'image
    except Exception as e:
        return {'pdf_error': str(e)}
    return {'text': text, 'images': images} 