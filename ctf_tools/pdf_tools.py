from PyPDF2 import PdfReader
import os

try:
    from PIL import Image
    import io
except ImportError:
    Image = None
    io = None

def extract_pdf_content(filepath, output_dir='extracted_images'):
    text = ''
    images = []
    try:
        reader = PdfReader(filepath)
        # Extraction du texte
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + '\n'
        # Extraction des images
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        for page_num, page in enumerate(reader.pages):
            if '/XObject' in page.get('/Resources', {}):
                xObject = page['/Resources']['/XObject'].get_object()
                for obj in xObject:
                    xobj = xObject[obj]
                    if xobj['/Subtype'] == '/Image':
                        img_data = xobj.get_data()
                        ext = 'jpg' if xobj.get('/Filter') == '/DCTDecode' else 'png'
                        img_path = os.path.join(output_dir, f"{os.path.basename(filepath)}_page{page_num+1}_{obj[1:]}.{ext}")
                        with open(img_path, 'wb') as img_file:
                            img_file.write(img_data)
                        images.append(img_path)
    except Exception as e:
        return {'pdf_error': str(e)}
    return {'text': text, 'images': images} 