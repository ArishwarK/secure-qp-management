import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

def generate_watermarked_pdf(paper_title: str, content: str, center_id: str, timestamp: str, printed_by: str) -> io.BytesIO:
    """
    Generates a secure PDF with dynamic diagonal background watermark
    and strict distribution metadata.
    """
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # 1. Dynamic Watermark Background
    pdf.saveState()
    pdf.setFont("Helvetica-Bold", 36)
    pdf.setFillColor(colors.Color(0.85, 0.85, 0.85, alpha=0.35))
    pdf.translate(width / 2, height / 2)
    pdf.rotate(45)
    watermark_text = f"EXAM CENTER: {center_id} | {timestamp}"
    pdf.drawCentredString(0, 0, watermark_text)
    pdf.drawCentredString(0, -60, f"PRINTED BY: {printed_by} [CONTROLLED]")
    pdf.restoreState()

    # 2. Header & Metadata
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, height - 50, f"CONFIDENTIAL EXAMINATION: {paper_title}")
    
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, height - 70, f"Exam Center: {center_id} | Decrypted & Printed: {timestamp} | Supervisor: {printed_by}")
    pdf.setLineWidth(1)
    pdf.line(50, height - 75, width - 50, height - 75)

    # 3. Question Paper Content
    pdf.setFont("Helvetica", 11)
    text_object = pdf.beginText(50, height - 100)
    text_object.setLeading(16)
    
    for line in content.split("\n"):
        text_object.textLine(line)
    
    pdf.drawText(text_object)

    # 4. Footer Tracking Notice
    pdf.setFont("Helvetica-Oblique", 8)
    pdf.setFillColor(colors.red)
    pdf.drawString(50, 30, "STRICTLY CONFIDENTIAL - UNAUTHORIZED SHARING, PHOTOGRAPHY, OR DUPLICATION IS A CRIMINAL OFFENSE.")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return buffer