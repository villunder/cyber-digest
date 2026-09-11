import os
import smtplib
import re
import html
import socket
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor, as_completed
import feedparser

# Setare timeout strict la nivel de rețea (max 8 secunde per server RSS)
socket.setdefaulttimeout(8)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

RSS_SOURCES = [
    # --- ROMÂNIA & REGIONALE ---
    ("DNSC România", "https://dnsc.ro/feed"),
    ("Softpedia Security", "https://news.softpedia.com/newsRSS/Security-12.xml"),
    ("ZoneIT Security", "https://zoneit.ro/category/securitate/feed/"),

    # --- SPECIFIC WEB STACK & MAIL ---
    ("Joomla Security Center", "https://developer.joomla.org/security-centre.feed?type=rss"),
    ("PHP Official News", "https://www.php.net/news.rss"),
    ("Packet Storm Exploits", "https://rss.packetstormsecurity.com/files/"),
    ("Packet Storm Security News", "https://rss.packetstormsecurity.com/news/"),

    # --- CERT-URI & ALERTE OFICIALE ---
    ("CISA Advisories (US-CERT)", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("SANS Internet Storm Center", "https://isc.sans.edu/rssfeed.xml"),
    ("Zero Day Initiative (ZDI)", "https://www.zerodayinitiative.com/blog?format=rss"),
    ("NCSC UK Advisories", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss.xml"),

    # --- THREAT INTELLIGENCE LABS ---
    ("Microsoft Security Blog", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Cisco Talos Intelligence", "https://feeds.feedburner.com/feedburner/Talos"),
    ("Palo Alto Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Google Cloud / Mandiant", "https://cloud.google.com/blog/topics/threat-intelligence/rss/"),
    ("SentinelOne Threat Research", "https://www.sentinelone.com/blog/category/threat-research/feed/"),
    ("CrowdStrike Blog", "https://www.crowdstrike.com/blog/feed/"),
    ("Kaspersky Securelist", "https://securelist.com/feed/"),
    ("ESET WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/"),

    # --- PUBLICAȚII GLOBALE ---
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    ("Ars Technica Security", "https://feeds.arstechnica.com/arstechnica/security"),
    ("The Register Security", "https://www.theregister.com/security/headlines.atom")
]

KEYWORDS_TARGETED = [
    "joomla", "php", "apache", "nginx", "exim", "postfix", "dovecot", 
    "mail", "htaccess", "modsecurity", "mysql", "mariadb", "cpanel", "wordpress"
]

KEYWORDS_CRITICAL = [
    "rce", "remote code execution", "zero-day", "0-day", "unauthenticated", 
    "sql injection", "sqli", "critical vulnerability", "active exploitation", 
    "arbitrary file read", "privilege escalation", "ransomware", "supply chain"
]

KEYWORDS_GENERAL = ["cve", "vulnerability", "exploit", "patch", "malware", "breach", "phishing", "attack"]

def clean_html(text):
    if not text:
        return ""
    text = html.unescape(text)
    clean = re.compile('<.*?>')
    cleaned_text = re.sub(clean, '', text)
    return " ".join(cleaned_text.split())

def is_recent(entry, hours=36):
    published_parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not published_parsed:
        return True
    pub_time = datetime(*published_parsed[:6], tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (now - pub_time) <= timedelta(hours=hours)

def fetch_single_feed(source):
    source_name, url = source
    fetched_items = []
    try:
        feed = feedparser.parse(url, agent=USER_AGENT)
        for entry in feed.entries:
            if not is_recent(entry, hours=36):
                continue

            link = entry.get("link", "")
            title = entry.get("title", "").strip()
            raw_summary = entry.get("summary", "") or entry.get("description", "")
            summary = clean_html(raw_summary)
            summary_truncated = summary[:280] + "..." if len(summary) > 280 else summary

            fetched_items.append({
                "title": title,
                "link": link,
                "source": source_name,
                "summary": summary_truncated,
                "full_text": f"{title} {summary}".lower()
            })
    except Exception:
        pass
    return fetched_items

def fetch_and_filter():
    targeted_news = []
    critical_news = []
    general_news = []
    seen_links = set()
    seen_titles = set()

    # Rulare descărcări în paralel (12 fire simultane)
    all_fetched = []
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(fetch_single_feed, src) for src in RSS_SOURCES]
        for future in as_completed(futures):
            all_fetched.extend(future.result())

    for item in all_fetched:
        link = item["link"]
        title_lower = item["title"].lower()

        if link in seen_links or title_lower in seen_titles:
            continue
        seen_links.add(link)
        seen_titles.add(title_lower)

        text = item["full_text"]
        is_targeted = any(kw in text for kw in KEYWORDS_TARGETED)
        is_critical = any(kw in text for kw in KEYWORDS_CRITICAL)
        is_gen = any(kw in text for kw in KEYWORDS_GENERAL)

        clean_item = {
            "title": item["title"],
            "link": item["link"],
            "source": item["source"],
            "summary": item["summary"]
        }

        if is_targeted:
            targeted_news.append(clean_item)
        elif is_critical:
            critical_news.append(clean_item)
        elif is_gen or item["source"] in ["DNSC România", "Joomla Security Center", "PHP Official News"]:
            general_news.append(clean_item)

    return targeted_news, critical_news, general_news

def build_web_dashboard(targeted_news, critical_news, gen_news):
    now_str = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    
    html_out = f"""<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="mobile-web-app-capable" content="yes">
    <title>Cyber Security Dashboard</title>
    <style>
        :root {{
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-red: #ef4444;
            --accent-orange: #f97316;
            --accent-blue: #38bdf8;
            --accent-green: #22c55e;
            --border: #334155;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 12px;
            line-height: 1.5;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        header {{
            background: var(--card-bg);
            padding: 16px 20px;
            border-radius: 12px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }}
        h1 {{ font-size: 1.25rem; margin: 0; }}
        .badge-time {{ font-size: 0.75rem; color: var(--text-muted); background: #0f172a; padding: 4px 8px; border-radius: 6px; }}
        .section-title {{
            font-size: 1rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            padding: 10px 14px;
            border-radius: 8px;
            margin-top: 24px;
            margin-bottom: 14px;
            font-weight: 700;
        }}
        .title-red {{ background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border-left: 4px solid var(--accent-red); }}
        .title-orange {{ background: rgba(249, 115, 22, 0.15); color: var(--accent-orange); border-left: 4px solid var(--accent-orange); }}
        .title-blue {{ background: rgba(56, 189, 248, 0.15); color: var(--accent-blue); border-left: 4px solid var(--accent-blue); }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 16px;
            margin-bottom: 12px;
        }}
        .card-source {{
            display: inline-block;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            background: #334155;
            color: #cbd5e1;
            padding: 2px 6px;
            border-radius: 4px;
            margin-bottom: 6px;
        }}
        .card-title {{
            color: var(--text-main);
            text-decoration: none;
            font-weight: 600;
            font-size: 0.95rem;
            display: block;
            margin-bottom: 6px;
        }}
        .card-title:hover {{ color: var(--accent-blue); }}
        .card-desc {{ font-size: 0.85rem; color: var(--text-muted); margin: 0; }}
        .ok-box {{
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: var(--accent-green);
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 0.9rem;
        }}
        footer {{ text-align: center; color: var(--text-muted); font-size: 0.75rem; margin-top: 30px; padding: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Cyber Security Dashboard</h1>
            <span class="badge-time">Actualizat: {now_str}</span>
        </header>
    """

    if targeted_news:
        html_out += '<div class="section-title title-red">🔴 Alerte Specifice (Joomla / PHP / Web / Mail)</div>'
        for item in targeted_news:
            html_out += f"""
            <div class="card">
                <span class="card-source">{item['source']}</span>
                <a class="card-title" href="{item['link']}" target="_blank">{item['title']}</a>
                <p class="card-desc">{item['summary']}</p>
            </div>
            """
    else:
        html_out += '<div class="ok-box">✅ Nicio alertă critică directă detectată pentru Joomla, PHP sau serverul web în ultimele 36 ore.</div>'

    if critical_news:
        html_out += '<div class="section-title title-orange">🟠 Threat Intelligence & 0-Day / RCE</div>'
        for item in critical_news[:12]:
            html_out += f"""
            <div class="card">
                <span class="card-source">{item['source']}</span>
                <a class="card-title" href="{item['link']}" target="_blank">{item['title']}</a>
                <p class="card-desc">{item['summary']}</p>
            </div>
            """

    if gen_news:
        html_out += '<div class="section-title title-blue">🔵 Știri & Fluxuri Global Security</div>'
        for item in gen_news[:15]:
            html_out += f"""
            <div class="card">
                <span class="card-source">{item['source']}</span>
                <a class="card-title" href="{item['link']}" target="_blank">{item['title']}</a>
            </div>
            """

    html_out += """
        <footer>Cyber Digest Monitoring System</footer>
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

    if not all([smtp_server, smtp_user, smtp_password, email_to]):
        print("Credențialele SMTP lipsesc. Emailul nu a fost trimis.")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = email_to
    msg.attach(MIMEText(html_content, "html"))

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, email_to, msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, email_to, msg.as_string())
        print("Email trimis cu succes.")
    except Exception as e:
        print(f"Eroare la trimiterea emailului: {e}")

if __name__ == "__main__":
    targeted_news, critical_news, gen_news = fetch_and_filter()
    
    html_dashboard = build_web_dashboard(targeted_news, critical_news, gen_news)
    with open("index.html", "w", encoding="utf-8") as f:
        f.write(html_dashboard)
    print("index.html generat în timp record.")

    current_utc_hour = datetime.now(timezone.utc).hour
    force_email = os.environ.get("FORCE_EMAIL", "false").lower() == "true"
    
    if current_utc_hour == 5 or force_email:
        send_email(f"🛡️ Daily Cyber Digest - {datetime.now().strftime('%d.%m.%Y')}", html_dashboard)
