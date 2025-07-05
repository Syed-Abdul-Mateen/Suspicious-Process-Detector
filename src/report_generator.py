# generate_report.py

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
import os

LOG_PATH = "logs/suspicious_log.txt"
REPORTS_DIR = "reports"

def create_pdf_report():
    if not os.path.exists(LOG_PATH):
        print("No suspicious logs found.")
        return

    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(REPORTS_DIR, f"suspicious_report_{timestamp}.pdf")

    c = canvas.Canvas(output_file, pagesize=letter)
    width, height = letter
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Suspicious Process Activity Report")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 70, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    c.setFont("Courier", 9)

    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    y = height - 100
    for line in lines:
        if y < 40:
            c.showPage()
            y = height - 50
            c.setFont("Courier", 9)
        c.drawString(50, y, line.strip())
        y -= 12

    c.save()
    print(f"PDF report generated: {output_file}")
