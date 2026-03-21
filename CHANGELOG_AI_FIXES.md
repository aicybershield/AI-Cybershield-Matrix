
# AI-CyberShield-Matrix — Fixes (2025-08-16)

## What I changed
1. **AI Fake Login Detector (backend/ai_fake_login_detector/ai_fake_login_detector/app.py)**
   - Added **dual-mode** detection:
     - **URL/Text mode** (`/detect_url`) with heuristics for suspicious domains.
     - **Image mode** (`/detect_image`) with OCR-based analysis (uses `pytesseract` + `Pillow` if available).
   - Template updated to show both input modes and an image preview + reasons.
   - Returns structured results with `mode`, `label`, `confidence`, `reasons`, and `ocr_excerpt`.

2. **Threat Detector Fallback (utils/phishing_detector.py)**
   - If the ML model (`phishing_model.pkl`) is missing, added a **rule-based fallback** with practical signals instead of returning “model not found”.

## Optional dependencies for image analysis
- Install **Tesseract OCR** on your system.
- `pip install pytesseract Pillow`

> Without OCR, the detector still works using heuristics but confidence is reduced.

## How to run
- Root app: `python app.py` then open `http://localhost:5000/fake-login-detector`.
- Or run the detector module directly:  
  `cd backend/ai_fake_login_detector/ai_fake_login_detector && python app.py`

## Notes
- Frontend pages render JSON results in a `<pre>` block by design (so you see discrete fields). If you prefer plain sentences, I can switch templates to human-readable strings.
