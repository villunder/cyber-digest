import os
import smtplib
import re
import html
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import feedparser

# User-Agent pentru a preveni blocarea cererilor RSS de către WAF-uri / Cloudflare
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Lista extinsă și structurată de surse RSS
RSS_SOURCES = [
    # --- 1. SURSE NAȚIONALE & REGIONALE (ROMÂNIA) ---
    ("DNSC România", "https://dnsc.ro/feed"),
    ("Softpedia Security", "https://news.softpedia.com/newsRSS/Security-12.xml"),
    ("ZoneIT Security", "https://zoneit.ro/category/securitate/feed/"),

    # --- 2. SPECIFIC WEB STACK, MAIL & DATABASE (Joomla, PHP, Server, DB) ---
    ("Joomla Security Center", "https://developer.joomla.org/security-centre.feed?type=rss"),
    ("PHP Official News", "https://www.php.net/news.rss"),
    ("Packet Storm Exploits", "https://rss.packetstormsecurity.com/files/"),
    ("Packet Storm Security News", "https://rss.packetstormsecurity.com/news/"),

    # --- 3. ALERTE OFICIALE, CERT-URI & VULNERABILITĂȚI (CVE / 0-DAY) ---
    ("CISA Advisories (US-CERT)", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed.xml"),
    ("Zero Day Initiative (ZDI)", "https://www.zerodayinitiative.com/blog?format=rss"),
    ("NCSC UK Advisories", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss.xml"),

    # --- 4. THREAT INTELLIGENCE & RESEARCH LABS (VENDORI TOP) ---
    ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Cisco Talos Intelligence", "https://feeds.feedburner.com/feedburner/Talos"),
    ("Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Google Cloud Security / Mandiant", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    ("SentinelOne Threat Research", "https://www.sentinelone.com/blog/category/threat-research/feed/"),
    ("CrowdStrike Blog", "https://www.crowdstrike.com/blog/feed/"),
    ("Kaspersky Securelist", "https://securelist.com/feed/"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/"),
    ("Sophos Threat Research", "https://news.sophos.com/en-us/feed/"),
    ("Trend Micro Research", "http://feeds.trendmicro.com/TrendMicroThreatResearch"),

    # --- 5. ŞTIRI GLOBALE DE TOP & JURNALISM CIBERNETIC ---
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    ("Ars Technica Security", "https://feeds.arstechnica.com/arstechnica/security"),
    ("The Register Security", "https://www.theregister.com/security/headlines.atom"),
    ("CyberScoop", "https://cyberscoop.com/feed/"),
    ("Schneier on Security", "https://www.schneier.com/feed/atom/")
]

# Matrice de cuvinte cheie pentru prioritate maximă (Stack Web & Mail)
KEYWORDS_TARGETED = [
    "joomla", "php", "apache", "nginx", "exim", "postfix", "dovecot", 
    "mail", "htaccess", "modsecurity", "mysql", "mariadb", "cpanel", "wordpress"
]

# Matrice de cuvinte cheie pentru amenințări critice globale
KEYWORDS_CRITICAL = [
    "rce", "remote code execution", "zero-day", "0-day", "unauthenticated", 
    "sql injection", "sqli", "critical vulnerability", "active exploitation", 
    "arbitrary file read", "privilege escalation", "ransomware", "supply chain",
    "kernel", "active directory", "cisa kev", "bypass"
]

KEYWORDS_GENERAL = ["cve", "vulnerability", "exploit", "patch", "malware", "breach", "phishing", "attack"]

def clean_html(text):
    """Elimină etichetele HTML și curăță textul pentru un email lizibil."""
    if not text:
        return ""
    text = html.unescape(text)
    clean = re.compile('<.*?>')
    cleaned_text = re.sub(clean, '', text)
    return " ".join(cleaned_text.split())

def is_recent(entry, hours=36):
    """Verifică dacă articolul a fost publicat în fereastra de timp specificată."""
    published_parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not published_parsed:
        return True
    pub_time = datetime(*published_parsed[:6], tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (now - pub_time) <= timedelta(hours=hours)

def fetch_and_filter():
    targeted_news = []
    critical_news = []
    general_news = []
    seen_links = set()
    seen_titles = set()

    for source_name, url in RSS_SOURCES:
        try:
            feed = feedparser.parse(url, agent=USER_AGENT)
            for entry in feed.entries:
                link = entry.get("link", "")
                title = entry.get("title", "").strip()
                
                # Deduplicare pe bază de URL și titlu
                title_lower = title.lower()
                if link in seen_links or title_lower in seen_titles:
                    continue
                seen_links.add(link)
                seen_titles.add(title_lower)

                if not is_recent(entry, hours=36):
                    continue

                raw_summary = entry.get("summary", "") or entry.get("description", "")
                summary = clean_html(raw_summary)
                summary_truncated = summary[:280] + "..." if len(summary) > 280 else summary
                text_to_search = f"{title} {summary}".lower()

                item = {
                    "title": title,
                    "link": link,
                    "source": source_name,
                    "summary": summary_truncated
                }

                # Evaluare priorități
                is_targeted = any(kw in text_to_search for kw in KEYWORDS_TARGETED)
                is_critical = any(kw in text_to_search for kw in KEYWORDS_CRITICAL)
                is_gen = any(kw in text_to_search for kw in KEYWORDS_GENERAL)

                if is_targeted:
                    targeted_news.append(item)
                elif is_critical:
                    critical_news.append(item)
                elif is_gen or source_name in ["DNSC România", "Joomla Security Center", "PHP Official News", "CISA Advisories (US-CERT)"]:
                    general_news.append(item)
        except Exception as e:
            print(f"Eroare la preluarea RSS de la {source_name}: {e}")

    return targeted_news, critical_news, general_news

def build_html_report(targeted_news, critical_news, gen_news):
    date_str = datetime.now().strftime("%d-%m-%Y")
    html_out = f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #222; line-height: 1.5; padding: 15px; background-color: #f8f9fa;">
        <div style="max-width: 720px; margin: 0 auto; background: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 20px;">
            <h2 style="color: #1a2a3a; border-bottom: 3px solid #0056b3; padding-bottom: 8px; margin-top: 0;">
                🛡️ Daily Cyber Security Digest - {date_str}
            </h2>
    """

    # Secțiunea 1: Alerte specifice pentru stack-ul web & mail
    if targeted_news:
        html_out += """
        <div style="margin-bottom: 25px;">
            <h3 style="color: #d9534f; background: #fdf7f7; padding: 8px 12px; border-left: 4px solid #d9534f; margin-bottom: 12px; font-size: 16px;">
                🔴 Alerte Specifice Infrastructurii (Joomla / PHP / Web / Mail)
            </h3>
            <ul style="padding-left: 20px;">
        """
        for item in targeted_news:
            html_out += f"""
            <li style="margin-bottom: 14px;">
                <span style="background: #e9ecef; color: #495057; font-size: 11px; padding: 2px 6px; border-radius: 3px; font-weight: bold;">{item['source']}</span>
                <a href="{item['link']}" style="color: #0056b3; text-decoration: none; font-weight: bold; font-size: 15px;"> {item['title']}</a><br>
                <div style="color: #555; font-size: 13px; margin-top: 4px;">{item['summary']}</div>
            </li>
            """
        html_out += "</ul></div>"
    else:
        html_out += """
        <div style="background: #eafaf1; border-left: 4px solid #28a745; padding: 10px; margin-bottom: 20px; font-size: 13px; color: #2e7d32;">
            ✅ <strong>Nicio alertă critică directă</strong> detectată pentru Joomla, PHP sau serverul web în ultimele 36 ore.
        </div>
        """

    # Secțiunea 2: Vulnerabilități critice globale & Threat Intelligence
    if critical_news:
        html_out += """
        <div style="margin-bottom: 25px;">
            <h3 style="color: #f0ad4e; background: #fefcf5; padding: 8px 12px; border-left: 4px solid #f0ad4e; margin-bottom: 12px; font-size: 16px;">
                🟠 Amenințări Critice & Threat Intelligence (0-Day / RCE / Ransomware)
            </h3>
            <ul style="padding-left: 20px;">
        """
        for item in critical_news[:10]:  # Primele 10 cele mai relevante
            html_out += f"""
            <li style="margin-bottom: 12px;">
                <span style="background: #e9ecef; color: #495057; font-size: 11px; padding: 2px 6px; border-radius: 3px; font-weight: bold;">{item['source']}</span>
                <a href="{item['link']}" style="color: #111; text-decoration: none; font-weight: bold; font-size: 14px;"> {item['title']}</a><br>
                <div style="color: #666; font-size: 12px; margin-top: 3px;">{item['summary']}</div>
            </li>
            """
        html_out += "</ul></div>"

    # Secțiunea 3: Știri generale din securitatea cibernetică
    if gen_news:
        html_out += """
        <div style="margin-bottom: 20px;">
            <h3 style="color: #0275d8; background: #f4f8fb; padding: 8px 12px; border-left: 4px solid #0275d8; margin-bottom: 12px; font-size: 16px;">
                🔵 Știri & Monitorizare Cyber Security Globală
            </h3>
            <ul style="padding-left: 20px;">
        """
        for item in gen_news[:12]:  # Primele 12 titluri
            html_out += f"""
            <li style="margin-bottom: 8px;">
                <span style="color: #777; font-size: 11px;">[{item['source']}]</span>
                <a href="{item['link']}" style="color: #0275d8; text-decoration: none; font-size: 13px;"> {item['title']}</a>
            </li>
            """
        html_out += "</ul></div>"

    html_out += """
            <hr style="border: 0; border-top: 1px solid #eee; margin-top: 25px;">
            <p style="font-size: 11px; color: #888; text-align: center; margin-bottom: 0;">
                Sinteză automatizată generată pentru protecția oamrcl.ro.
            </p>
        </div>
    </body>
    </html>
    """
    return html_out

def send_email(subject, html_content):
    smtp_server = os.environ.get("SMTP_SERVER")
    smtp_port = int(os.environ.get("SMTP_PORT", 465))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    email_to = os.environ.get("EMAIL_TO")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = email_to
    msg.attach(MIMEText(html_content, "html"))

    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, email_to, msg.as_string())
    else:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, email_to, msg.as_string())

if __name__ == "__main__":
    targeted_news, critical_news, gen_news = fetch_and_filter()
    if targeted_news or critical_news or gen_news:
        html_report = build_html_report(targeted_news, critical_news, gen_news)
        send_email(f"🛡️ Daily Cyber Digest - {datetime.now().strftime('%d.%m.%Y')}", html_report)
        print("Raport trimis cu succes pe email.")
    else:
        print("Nu au fost găsite noutăți relevante în ultimele 36 ore.")
