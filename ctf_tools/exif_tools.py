from PIL import Image
from PIL.ExifTags import TAGS

def extract_exif(filepath):
    try:
        image = Image.open(filepath)
        exif_data = image._getexif()
        if not exif_data:
            return {}
        exif = {}
        for tag_id, value in exif_data.items():
            tag = TAGS.get(tag_id, tag_id)
            exif[str(tag)] = str(value)
        return exif
    except Exception as e:
        return {'exif_error': str(e)}   