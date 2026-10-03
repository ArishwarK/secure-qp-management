import { PDFDocument, rgb, StandardFonts, degrees } from 'pdf-lib';

/**
 * Generates a secure PDF with dynamic diagonal background watermark
 * and strict forensic distribution metadata.
 */
export async function generateWatermarkedPdf({ paperTitle, content, centerId, timestamp, printedBy }) {
  const pdfDoc = await PDFDocument.create();
  const page = pdfDoc.addPage([612, 792]); // Standard US Letter
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontOblique = await pdfDoc.embedFont(StandardFonts.HelveticaOblique);

  const { width, height } = page.getSize();

  // 1. Dynamic Watermark Background (Rotated 45 degrees across center)
  const watermarkText1 = `EXAM CENTER: ${centerId} | ${timestamp}`;
  const watermarkText2 = `PRINTED BY: ${printedBy} [CONTROLLED]`;

  page.drawText(watermarkText1, {
    x: 80,
    y: 260,
    size: 20,
    font: fontBold,
    color: rgb(0.85, 0.85, 0.85),
    rotate: degrees(45),
  });

  page.drawText(watermarkText2, {
    x: 140,
    y: 200,
    size: 18,
    font: fontBold,
    color: rgb(0.88, 0.88, 0.88),
    rotate: degrees(45),
  });

  // 2. Header & Metadata
  page.drawText(`CONFIDENTIAL EXAMINATION: ${paperTitle}`, {
    x: 50,
    y: height - 50,
    size: 14,
    font: fontBold,
    color: rgb(0.1, 0.1, 0.1),
  });

  page.drawText(`Exam Center: ${centerId} | Decrypted & Printed: ${timestamp} | Supervisor: ${printedBy}`, {
    x: 50,
    y: height - 70,
    size: 9.5,
    font: fontRegular,
    color: rgb(0.35, 0.35, 0.35),
  });

  page.drawLine({
    start: { x: 50, y: height - 75 },
    end: { x: width - 50, y: height - 75 },
    thickness: 1,
    color: rgb(0.75, 0.75, 0.75),
  });

  // 3. Question Paper Content
  const lines = (content || '').split('\n');
  let y = height - 105;
  for (const line of lines) {
    if (y < 60) break;
    page.drawText(line, {
      x: 50,
      y,
      size: 11,
      font: fontRegular,
      color: rgb(0.1, 0.1, 0.1),
    });
    y -= 18;
  }

  // 4. Footer Tracking Notice
  page.drawText('STRICTLY CONFIDENTIAL - UNAUTHORIZED SHARING, PHOTOGRAPHY, OR DUPLICATION IS A CRIMINAL OFFENSE.', {
    x: 50,
    y: 30,
    size: 7.5,
    font: fontOblique,
    color: rgb(0.8, 0.1, 0.1),
  });

  const pdfBytes = await pdfDoc.save();
  return Buffer.from(pdfBytes);
}

/**
 * Overlays dynamic diagonal background watermark and forensic headers/footers
 * onto an existing uploaded PDF buffer.
 */
export async function watermarkExistingPdf({ pdfBuffer, paperTitle, centerId, timestamp, printedBy }) {
  const pdfDoc = await PDFDocument.load(pdfBuffer);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
  const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontOblique = await pdfDoc.embedFont(StandardFonts.HelveticaOblique);

  const pages = pdfDoc.getPages();
  const watermarkText1 = `EXAM CENTER: ${centerId} | ${timestamp}`;
  const watermarkText2 = `PRINTED BY: ${printedBy} [CONTROLLED]`;

  for (const page of pages) {
    const { width, height } = page.getSize();

    page.drawText(watermarkText1, {
      x: 60,
      y: height / 3,
      size: 18,
      font: fontBold,
      color: rgb(0.75, 0.75, 0.75),
      opacity: 0.45,
      rotate: degrees(45),
    });

    page.drawText(watermarkText2, {
      x: 110,
      y: height / 3 - 50,
      size: 16,
      font: fontBold,
      color: rgb(0.75, 0.75, 0.75),
      opacity: 0.45,
      rotate: degrees(45),
    });

    page.drawText(`CONFIDENTIAL: ${paperTitle} | Center: ${centerId} | Printed: ${timestamp} by ${printedBy}`, {
      x: 30,
      y: height - 20,
      size: 8,
      font: fontRegular,
      color: rgb(0.5, 0.1, 0.1),
    });

    page.drawText('STRICTLY CONFIDENTIAL - UNAUTHORIZED SHARING, PHOTOGRAPHY, OR DUPLICATION IS A CRIMINAL OFFENSE.', {
      x: 30,
      y: 15,
      size: 7.5,
      font: fontOblique,
      color: rgb(0.8, 0.1, 0.1),
    });
  }

  const pdfBytes = await pdfDoc.save();
  return Buffer.from(pdfBytes);
}

