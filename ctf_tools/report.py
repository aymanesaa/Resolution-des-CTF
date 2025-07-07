import json
import datetime

def save_report(data, filename='report.json'):
    report = {
        'timestamp': datetime.datetime.now().isoformat(),
        'results': data
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4, ensure_ascii=False) 