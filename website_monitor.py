#!/usr/bin/env python3
"""
Website Change Monitor - FINAL VERSION

Monitors websites for changes using hash-based detection on normalized HTML.
Detects and reports only NEW added textual content via beautifully formatted HTML emails.
Uses SMTP_SSL for secure delivery. Works reliably with Outlook and excludes HTML fragments,
image alt text, captions, and navigation noise from notifications.
"""

import os
import json
import hashlib
import requests
import time
import smtplib
import html
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional
from bs4 import BeautifulSoup, Comment


class WebsiteMonitor:
    def __init__(self, config_file: str = "config.json"):
        """
        Initialize the website monitor with configuration and state files.

        Args:
            config_file (str): Path to the JSON configuration file (default: "config.json").
        """
        self.config_file = config_file
        self.data_file = "website_data.json"
        self.config = self.load_config()
        self.website_data = self.load_website_data()

    def load_config(self) -> dict:
        """
        Load the configuration from the JSON file. If the file does not exist,
        create a default configuration with example values and exit.

        Returns:
            dict: The loaded configuration dictionary.

        Exits the program if a new config file is created.
        """
        if not os.path.exists(self.config_file):
            default_config = {
                "websites": [
                    {"url": "https://example.com", "name": "Example Site", "selector": None}
                ],
                "notifications": {
                    "email": {
                        "enabled": True,
                        "smtp_server": "smtp.gmail.com",
                        "smtp_port": 465,
                        "sender_email": "your_email@gmail.com",
                        "sender_password": "your_app_password",
                        "recipient_email": "recipient@example.com",
                        "use_ssl": True
                    }
                },
                "check_interval": 3600,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/130.0 Safari/537.36",
                "ignore_dynamic_content": True,
                "min_change_chars": 50
            }
            with open(self.config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            print(f"Created {self.config_file} - please edit with your details")
            exit(0)

        with open(self.config_file, 'r') as f:
            return json.load(f)

    def load_website_data(self) -> dict:
        """
        Load previously stored website data (hashes, last check, clean text) from disk.

        Returns:
            dict: Dictionary mapping URLs to their stored data. Empty dict if file doesn't exist.
        """
        if os.path.exists(self.data_file):
            with open(self.data_file, 'r') as f:
                return json.load(f)
        return {}

    def save_website_data(self):
        """
        Save the current website data (hashes, timestamps, clean text, etc.) to disk.
        """
        with open(self.data_file, 'w') as f:
            json.dump(self.website_data, f, indent=4)

    def normalize_content(self, content: str) -> str:
        """
        Remove dynamic and noisy HTML elements that commonly change without meaningful updates
        (scripts, timestamps, session IDs, etc.) before hashing and comparison.

        Args:
            content (str): Raw HTML content from the webpage.

        Returns:
            str: Normalized HTML string suitable for reliable change detection.
        """
        if not self.config.get('ignore_dynamic_content', True):
            return content
        try:
            soup = BeautifulSoup(content, 'html.parser')
            # Remove scripts, styles, etc.
            for tag in soup(['script', 'style', 'noscript', 'svg', 'meta', 'link']):
                tag.decompose()
            # Remove elements with dynamic patterns
            patterns = ['timestamp', 'time', 'date', 'session', 'csrf', 'token', 'nonce', 'updated', 'modified']
            for tag in soup.find_all(True):
                if tag.get('class') and any(p in ' '.join(tag['class']).lower() for p in patterns):
                    tag.decompose()
                if tag.get('id') and any(p in tag.get('id', '').lower() for p in patterns):
                    tag.decompose()
            return str(soup)
        except:
            return content

    def get_clean_text(self, content: str) -> str:
        """
        Extract only visible, meaningful human-readable text from HTML.
        Removes images, figures, captions, navigation, ads, and HTML fragments.
        Used for change detection and email previews.

        Args:
            content (str): HTML content (normalized or raw).

        Returns:
            str: Clean plain text string.
        """
        try:
            soup = BeautifulSoup(content, 'html.parser')

            # Remove all noisy tags completely
            for tag in soup(['script', 'style', 'noscript', 'svg', 'meta', 'link',
                             'img', 'figure', 'figcaption', 'nav', 'header', 'footer', 'aside']):
                tag.decompose()

            # Collect only visible text nodes
            texts = []
            for element in soup.find_all(text=True):
                if element.parent.name in ['script', 'style']:
                    continue
                if isinstance(element, Comment):
                    continue
                text = element.strip()
                if text:
                    texts.append(text)

            full_text = ' '.join(texts)
            full_text = re.sub(r'\s+', ' ', full_text).strip()

            # Remove common UI noise
            full_text = re.sub(r'(cookie|privacy|accept|decline|login|sign up|subscribe|menu|search|advertisement|ad)', '', full_text, flags=re.I)
            full_text = re.sub(r'\s+', ' ', full_text).strip()

            return full_text or "No visible text"
        except:
            return "Error extracting clean text"

    def fetch_website_content(self, url: str, selector: Optional[str] = None) -> Optional[str]:
        """
        Fetch the webpage content and apply normalization.
        If a CSS selector is provided, limit comparison to that section.

        Args:
            url (str): The URL to fetch.
            selector (str or None): Optional CSS selector to monitor a specific part of the page.

        Returns:
            str or None: Normalized HTML content, or None if fetch failed.
        """
        try:
            headers = {'User-Agent': self.config.get('user_agent', '')}
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            content = self.normalize_content(response.text)
            if selector:
                soup = BeautifulSoup(content, 'html.parser')
                selected = soup.select(selector)
                if selected:
                    content = str(selected[0])  # Use selected element for hashing/comparison
            return content
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return None

    def calculate_hash(self, content: str) -> str:
        """
        Compute SHA-256 hash of the content for fast change detection.

        Args:
            content (str): Normalized content string.

        Returns:
            str: Hexadecimal hash digest.
        """
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def get_content_snippet(self, content: str) -> str:
        """
        Generate a clean, readable preview of the current page for inclusion in emails.

        Args:
            content (str): HTML content.

        Returns:
            str: Truncated clean text preview (max 1000 chars).
        """
        return self.get_clean_text(content)[:1000] + ("..." if len(self.get_clean_text(content)) > 1000 else "")

    def get_change_description(self, old_len: int, new_len: int) -> str:
        """
        Provide a human-readable summary of the size change.

        Args:
            old_len (int): Length of previous clean text.
            new_len (int): Length of current clean text.

        Returns:
            str: Descriptive summary string.
        """
        diff = new_len - old_len
        if diff > 500:
            return f"Significant new content added (~{diff:,} characters)"
        elif diff > 0:
            return f"New content added (~{diff:,} characters)"
        return "New or modified content detected"

    def find_content_differences(self, old_text: str, new_text: str) -> list:
        """
        Identify meaningful sentences that appear in new_text but not in old_text.

        Args:
            old_text (str): Previous clean text.
            new_text (str): Current clean text.

        Returns:
            list[str]: List of formatted "Added: ..." strings (up to 10).
        """
        def split_sentences(t: str):
            return [s.strip() for s in re.split(r'(?<=[.!?])\s+(?=[A-Z])', t) if len(s.strip()) > 30]

        old_set = set(split_sentences(old_text))
        added = [s for s in split_sentences(new_text) if s not in old_set]

        diffs = []
        for s in sorted(added, key=len, reverse=True)[:10]:
            disp = s if len(s) <= 350 else s[:350] + "..."
            diffs.append(f"Added: \"{disp}\"")

        return diffs or ["Minor new text added"]

    def check_website(self, website: dict) -> Optional[dict]:
        """
        Check a single website for changes.

        Args:
            website (dict): Dictionary containing at least 'url', optionally 'name' and 'selector'.

        Returns:
            dict or None: Change information if new content detected, None otherwise.
        """
        url = website['url']
        name = website.get('name', url)
        selector = website.get('selector')
        print(f"Checking {name} ({url})...")
        content = self.fetch_website_content(url, selector)
        if content is None:
            return None
        content_hash = self.calculate_hash(content)
        clean_text = self.get_clean_text(content)
        snippet = self.get_content_snippet(content)
        min_change = self.config.get('min_change_chars', 50)

        if url in self.website_data:
            prev = self.website_data[url]
            if content_hash == prev['hash']:
                print("  No changes")
                self.website_data[url]['last_check'] = datetime.now().isoformat()
                return None
            size_diff = abs(len(content) - len(prev.get('full_content', '')))
            if size_diff < min_change:
                print(f"  Tiny change ignored ({size_diff} chars)")
            else:
                print("  New content detected!")
                change_info = {
                    'url': url, 'name': name,
                    'previous_check': prev['last_check'],
                    'current_check': datetime.now().isoformat(),
                    'previous_full_content': prev.get('clean_text', ''),
                    'current_full_content': clean_text,
                    'current_snippet': snippet,
                }
                self.website_data[url] = {
                    'hash': content_hash, 'last_check': datetime.now().isoformat(),
                    'content_snippet': snippet, 'full_content': content, 'clean_text': clean_text
                }
                return change_info
        else:
            print("  First check - baseline saved")

        self.website_data[url] = {
            'hash': content_hash, 'last_check': datetime.now().isoformat(),
            'content_snippet': snippet, 'full_content': content, 'clean_text': clean_text
        }
        return None

    def send_email(self, subject: str, plain_text: str, html_text: str):
        """
        Send an email notification using SMTP_SSL.

        Args:
            subject (str): Email subject line.
            plain_text (str): Plain text body.
            html_text (str): HTML body.
        """
        try:
            cfg = self.config['notifications']['email']
            msg = MIMEMultipart("alternative")
            msg['Subject'] = subject
            msg['From'] = cfg['sender_email']
            msg['To'] = cfg['recipient_email']

            msg.attach(MIMEText(plain_text, "plain", "utf-8"))
            msg.attach(MIMEText(html_text, "html", "utf-8"))

            server = smtplib.SMTP_SSL(cfg['smtp_server'], cfg['smtp_port'])
            server.login(cfg['sender_email'], cfg['sender_password'])
            server.send_message(msg)
            server.quit()
            print("  Email sent successfully")
        except Exception as e:
            print(f"  Email failed: {e}")

    def send_notifications(self, change_info: dict):
        """
        Compose and send email notification for a detected change.

        Args:
            change_info (dict): Dictionary containing change details.
        """
        subject = f"New Content – {change_info['name']}"

        desc = self.get_change_description(
            len(change_info['previous_full_content']),
            len(change_info['current_full_content'])
        )
        differences = self.find_content_differences(
            change_info['previous_full_content'],
            change_info['current_full_content']
        )

        plain_body = f"""New Content Detected!

Site: {change_info['name']}
URL: {change_info['url']}
Detected: {change_info['current_check'][:19].replace('T', ' ')}

{desc}

New additions:
"""
        for i, line in enumerate(differences, 1):
            plain_body += f"{i}. {line}\n"
        plain_body += f"\nCurrent page preview:\n{change_info['current_snippet']}"

        html_body = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>New Content Detected</title>
</head>
<body style="font-family: Calibri, Arial, sans-serif; color: #333; line-height: 1.6; max-width: 700px; margin: 40px auto; padding: 20px;">
    <h2 style="color: #1a73e8; border-bottom: 3px solid #1a73e8; padding-bottom: 10px;">
        New Content Detected
    </h2>

    <div style="background: #f8f9fa; padding: 16px; border-radius: 8px; margin: 20px 0;">
        <p><strong>Site:</strong> {html.escape(change_info['name'])}</p>
        <p><strong>URL:</strong> <a href="{change_info['url']}">{html.escape(change_info['url'])}</a></p>
        <p><strong>Detected:</strong> {change_info['current_check'][:19].replace('T', ' ')}</p>
    </div>

    <div style="background: #e8f5e8; padding: 16px; border-left: 5px solid #34a853; border-radius: 4px; margin: 20px 0;">
        <strong>Summary:</strong> {html.escape(desc)}
    </div>

    <h3 style="color: #1a73e8;">New Content Added:</h3>
    <div style="background: #f0f4ff; padding: 16px; border-radius: 8px; margin-bottom: 20px;">
"""
        for i, diff in enumerate(differences, 1):
            html_body += f"        <p style='margin: 8px 0;'><strong>{i}.</strong> {html.escape(diff)}</p>\n"

        html_body += f"""    </div>

    <h3 style="color: #1a73e8;">Current Page Preview:</h3>
    <div style="background: white; padding: 16px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px; white-space: pre-wrap;">
        {html.escape(change_info['current_snippet'])}
    </div>

    <div style="text-align: center; margin: 40px 0;">
        <a href="{change_info['url']}" style="background: #1a73e8; color: white; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 16px;">
            View Full Page
        </a>
    </div>
</body>
</html>"""

        if self.config['notifications']['email']['enabled']:
            self.send_email(subject, plain_body, html_body)

    def run_check(self):
        """
        Perform a single check of all configured websites.
        Saves state and sends notifications for any detected changes.
        """
        print(f"\n{'='*60}")
        print(f"Check started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        changes = []
        for site in self.config['websites']:
            change_info = self.check_website(site)
            if change_info is not None:
                changes.append(change_info)

        self.save_website_data()

        if changes:
            print(f"\nNEW CONTENT on {len(changes)} site(s)!\n")
            for c in changes:
                print(f"→ {c['name']}")
                self.send_notifications(c)
        else:
            print("No new content detected.")

        print(f"\nCheck completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

    def run_continuous(self):
        """
        Run continuous monitoring loop with sleep intervals defined in config.
        Stops gracefully on KeyboardInterrupt (Ctrl+C).
        """
        print("Continuous monitoring started (Ctrl+C to stop)\n")
        try:
            while True:
                self.run_check()
                interval = self.config.get('check_interval', 3600)
                print(f"Next check in {interval//60} minutes...\n")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")


def main():
    """
    Entry point of the script. Parses command-line arguments and starts monitoring.
    """
    import argparse
    parser = argparse.ArgumentParser(description="Website Change Monitor")
    parser.add_argument('--config', default='config.json', help='Path to config file')
    parser.add_argument('--once', action='store_true', help='Run one check and exit')
    parser.add_argument('--continuous', action='store_true', help='Run continuously')
    args = parser.parse_args()

    monitor = WebsiteMonitor(args.config)
    if args.once:
        monitor.run_check()
    elif args.continuous:
        monitor.run_continuous()
    else:
        monitor.run_check()


if __name__ == "__main__":
    main()