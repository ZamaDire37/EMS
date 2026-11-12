const Tesseract = require('tesseract.js');

/**
 * Normalize common date strings (DD/MM/YYYY, YYYY-MM-DD, DD-MMM-YYYY, MM/YYYY) to YYYY-MM-DD
 */
function normalizeDate(raw) {
  if (!raw) return null;
  const s = raw.trim();

  // YYYY-MM-DD or YYYY/MM/DD
  let m = s.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$/);
  if (m) {
    return `${m[1]}-${m[2].padStart(2, '0')}-${m[3].padStart(2, '0')}`;
  }

  // DD/MM/YYYY or DD-MM-YYYY or DD.MM.YYYY
  m = s.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$/);
  if (m) {
    const d = parseInt(m[1], 10);
    const mo = parseInt(m[2], 10);
    if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31) {
      return `${m[3]}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
    }
    if (d >= 1 && d <= 12 && mo >= 1 && mo <= 31) {
      return `${m[3]}-${String(d).padStart(2, '0')}-${String(mo).padStart(2, '0')}`;
    }
  }

  // DD MMM YYYY (e.g., 14 Aug 2027)
  const months = {
    jan: '01', feb: '02', mar: '03', apr: '04', may: '05', jun: '06',
    jul: '07', aug: '08', sep: '09', oct: '10', nov: '11', dec: '12'
  };
  m = s.match(/^(\d{1,2})\s+([A-Za-z]{3,9})\s+(\d{4})$/);
  if (m) {
    const mo = months[m[2].slice(0, 3).toLowerCase()];
    if (mo) {
      return `${m[3]}-${mo}-${m[1].padStart(2, '0')}`;
    }
  }

  return null;
}

function parseDocumentFields(text) {
  const clean = (text || '').replace(/\r/g, '\n');
  const lower = clean.toLowerCase();

  // Document Type detection
  let docType = '';
  if (lower.includes('roadworth') || lower.includes('cor')) docType = 'Roadworthiness Certificate';
  else if (lower.includes('licence disc') || lower.includes('license disc') || lower.includes('motor vehicle licence')) docType = 'Licence Disc';
  else if (lower.includes('medical certificate') || lower.includes('fitness') || lower.includes('occupational health')) docType = 'Medical Certificate';
  else if (lower.includes('training') || lower.includes('bls') || lower.includes('acls') || lower.includes('pals') || lower.includes('cpd')) docType = 'Training Certificate';
  else if (lower.includes('renewal')) docType = 'Renewal Document';
  else if (lower.includes('licence') || lower.includes('license') || lower.includes('hpcsa') || lower.includes('hcpc') || lower.includes('registration')) docType = 'Professional Licence';
  else if (lower.includes('invoice') || lower.includes('receipt') || lower.includes('service')) docType = 'Service Receipt';

  // Staff name detection
  let staffName = '';
  const nameMatch = clean.match(/(?:name|holder|practitioner|employee|staff)\s*[:\-]\s*([A-Z][A-Za-z\s.'-]{2,40})/i);
  if (nameMatch) {
    staffName = nameMatch[1].split('\n')[0].trim();
  }

  // Licence / Certificate / Document number
  let docNumber = '';
  const numMatch = clean.match(/(?:licen[cs]e\s*(?:no|number|#)|cert(?:ificate)?\s*(?:no|number|#)|reg(?:istration)?\s*(?:no|number|#)|ref(?:erence)?\s*(?:no|#))\s*[:\-]?\s*([A-Z0-9\-\/]{4,25})/i);
  if (numMatch) {
    docNumber = numMatch[1].trim();
  }

  // Issue Date & Expiry Date
  let issueDate = '';
  let expiryDate = '';

  const issueMatch = clean.match(/(?:issue\s*date|issued\s*(?:on)?|date\s*of\s*issue|valid\s*from)\s*[:\-]?\s*(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})/i);
  if (issueMatch) {
    issueDate = normalizeDate(issueMatch[1]) || '';
  }

  const expiryMatch = clean.match(/(?:expir(?:y|es|ation)\s*(?:date)?|valid\s*(?:until|to|thru)|renewal\s*date)\s*[:\-]?\s*(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})/i);
  if (expiryMatch) {
    expiryDate = normalizeDate(expiryMatch[1]) || '';
  }

  // Fallback: scan all dates if expiryDate wasn't explicitly labeled
  if (!expiryDate) {
    const allDates = clean.match(/\b(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})\b/g) || [];
    const normalized = allDates.map(normalizeDate).filter(Boolean).sort();
    if (normalized.length === 1 && !issueDate) {
      expiryDate = normalized[0];
    } else if (normalized.length >= 2) {
      if (!issueDate) issueDate = normalized[0];
      expiryDate = normalized[normalized.length - 1];
    }
  }

  return {
    docType,
    staffName,
    docNumber,
    issueDate,
    expiryDate
  };
}

/**
 * Run OCR on an image Buffer.
 * Returns { success, confidence, rawText, extracted, warning }
 */
async function extractDocumentOcr(buffer, mimeType) {
  if (!mimeType || !mimeType.startsWith('image/')) {
    return {
      success: false,
      confidence: 0,
      rawText: '',
      extracted: { docType: '', staffName: '', docNumber: '', issueDate: '', expiryDate: '' },
      warning: 'OCR image recognition supports PNG/JPEG/WebP images. For PDF files, please enter document details manually.'
    };
  }

  try {
    const result = await Tesseract.recognize(buffer, 'eng', {
      logger: () => {} // suppress verbose stdout
    });
    const text = result.data.text || '';
    const confidence = typeof result.data.confidence === 'number' ? Math.round(result.data.confidence) : 0;
    const extracted = parseDocumentFields(text);

    return {
      success: true,
      confidence,
      rawText: text.trim(),
      extracted,
      warning: confidence < 55
        ? 'Low OCR confidence — please carefully verify and correct all extracted fields before saving.'
        : 'OCR extraction complete. Please review and confirm all fields before saving.'
    };
  } catch (err) {
    return {
      success: false,
      confidence: 0,
      rawText: '',
      extracted: { docType: '', staffName: '', docNumber: '', issueDate: '', expiryDate: '' },
      warning: 'OCR could not read this image clearly. Please enter the document details manually.'
    };
  }
}

module.exports = {
  extractDocumentOcr,
  parseDocumentFields
};
