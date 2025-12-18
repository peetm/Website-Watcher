# Website Change Monitor (needs some work)

A lightweight, reliable Python tool that monitors websites for changes and sends **beautiful, Outlook-friendly HTML email notifications** when **new content is added**.

Perfect for tracking:
- Government announcements
- Job postings
- Product availability / price changes
- Blog updates
- Regulatory pages
- Any site where you want to know immediately when new text appears

Only **new added sentences** are highlighted — no removed content, no HTML tags, no image alt text or navigation noise.

*(Actual emails render cleanly in Outlook, Gmail, and other clients)*

## Features

- **Fast & Reliable Detection**: Uses SHA-256 hashing on normalized HTML for instant, accurate change detection
- **Smart Text Extraction**: Extracts only visible, meaningful text — ignores scripts, ads, cookies banners, images, captions
- **Focus on New Content**: Reports only **added** sentences (great for announcements and updates)
- **Beautiful HTML Emails**: Professional layout with summary, added content list, and clean page preview
- **Secure Email Delivery**: Uses `SMTP_SSL` (port 465) — ideal for Gmail with App Passwords
- **Configurable**: Monitor full pages or specific sections via CSS selectors
- **Minimal False Positives**: Ignores tiny/dynamic changes (configurable threshold)
- **Continuous or One-Time Mode**: Run once or monitor forever

## Requirements

- Python 3.7+
- `requests`
- `beautifulsoup4`

Install dependencies:
```bash
pip install requests beautifulsoup4
