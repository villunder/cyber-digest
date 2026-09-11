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

# Setare timeout strict pe rețea (max 8 secunde per flux RSS)
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

def is_very_recent(entry, hours=6):
    published_parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not published_parsed:
        return False
    pub_time = datetime(*published_parsed[:6], tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return (now - pub_time) <= timedelta(hours=hours)

def format_cve(text):
    if not text:
        return ""
    cve_pattern = r'\b(CVE-\d{4}-\d{4,7})\b'
    replacement = r'<span onclick="event.stopPropagation(); window.open(\'https://nvd.nist.gov/vuln/detail/\1\', \'_blank\');" class="cve-badge">\1</span>'
    return re.sub(cve_pattern, replacement, text, flags=re.IGNORECASE)

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
            summary_truncated = summary[:320] + "..." if len(summary) > 320 else summary

            fetched_items.append({
                "title": title,
                "link": link,
                "source": source_name,
                "summary": summary_truncated,
                "full_text": f"{title} {summary}".lower(),
                "is_new": is_very_recent(entry, hours=6)
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
            "summary": item["summary"],
            "is_new": item["is_new"]
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
    
    count_targeted = len(targeted_news)
    count_critical = len(critical_news[:12])
    count_gen = len(gen_news[:15])
    count_total = count_targeted + count_critical + count_gen

    html_out = f"""<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="300">
    <meta name="mobile-web-app-capable" content="yes">
    <title>Cyber Security Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #080c14;
            --card-bg: #111827;
            --card-hover: #1f2937;
            --text-main: #ffffff;
            --text-muted: #a0aec0;
            --text-sub: #e2e8f0;
            --accent-red: #f43f5e;
            --accent-orange: #fb923c;
            --accent-blue: #38bdf8;
            --accent-green: #10b981;
            --border: rgba(255, 255, 255, 0.12);
            --border-hover: rgba(56, 189, 248, 0.45);
        }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            margin: 0;
            padding: 24px 16px;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        
        /* HEADER & STATS BAR */
        header {{
            background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
            padding: 22px 28px;
            border-radius: 16px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5);
        }}
        .header-title {{ display: flex; align-items: center; gap: 12px; }}
        .pulse-dot {{
            width: 12px;
            height: 12px;
            background-color: var(--accent-green);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--accent-green);
            animation: pulse 2s infinite;
        }}
        @keyframes pulse {{
            0% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }}
            70% {{ transform: scale(1); box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }}
            100% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }}
        }}
        h1 {{
            font-size: 1.55rem;
            font-weight: 800;
            margin: 0;
            letter-spacing: -0.02em;
            background: linear-gradient(to right, #ffffff, #cbd5e1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .badge-time {{
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--text-muted);
            background: rgba(15, 23, 42, 0.8);
            padding: 8px 14px;
            border-radius: 10px;
            border: 1px solid var(--border);
        }}

        /* COUNTERS STATS BAR */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 14px 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            cursor: pointer;
            transition: all 0.2s ease;
        }}
        .stat-card:hover {{
            background: var(--card-hover);
            transform: translateY(-2px);
        }}
        .stat-val {{ font-size: 1.6rem; font-weight: 800; }}
        .stat-lbl {{ font-size: 0.85rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); }}
        .stat-red .stat-val {{ color: var(--accent-red); }}
        .stat-orange .stat-val {{ color: var(--accent-orange); }}
        .stat-blue .stat-val {{ color: var(--accent-blue); }}
        .stat-total .stat-val {{ color: var(--accent-green); }}

        /* SEARCH & FILTER CONTROLS */
        .controls-panel {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 16px;
            margin-bottom: 28px;
            display: flex;
            flex-direction: column;
            gap: 14px;
        }}
        .search-box input {{
            width: 100%;
            background: #0f172a;
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 14px 18px;
            border-radius: 10px;
            font-size: 1rem;
            outline: none;
            font-family: inherit;
            transition: border-color 0.2s;
        }}
        .search-box input:focus {{
            border-color: var(--accent-blue);
        }}
        .tabs-row {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .tab-btn {{
            background: #0f172a;
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 9px 16px;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s;
            font-family: inherit;
        }}
        .tab-btn:hover {{ color: var(--text-main); background: #1e293b; }}
        .tab-btn.active {{
            background: var(--accent-blue);
            color: #080c14;
            border-color: var(--accent-blue);
        }}

        /* SECTIONS & CARDS */
        .section-title {{
            font-size: 1.15rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            padding: 14px 20px;
            border-radius: 12px;
            margin-top: 32px;
            margin-bottom: 18px;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .title-red {{
            background: linear-gradient(90deg, rgba(244, 63, 94, 0.18) 0%, rgba(244, 63, 94, 0.02) 100%);
            color: #ff6b81;
            border-left: 5px solid var(--accent-red);
            border-top: 1px solid rgba(244, 63, 94, 0.25);
        }}
        .title-orange {{
            background: linear-gradient(90deg, rgba(251, 146, 60, 0.18) 0%, rgba(251, 146, 60, 0.02) 100%);
            color: #ffaa5b;
            border-left: 5px solid var(--accent-orange);
            border-top: 1px solid rgba(251, 146, 60, 0.25);
        }}
        .title-blue {{
            background: linear-gradient(90deg, rgba(56, 189, 248, 0.18) 0%, rgba(56, 189, 248, 0.02) 100%);
            color: #60a5fa;
            border-left: 5px solid var(--accent-blue);
            border-top: 1px solid rgba(56, 189, 248, 0.25);
        }}

        /* CARD LINK COMPLETE */
        .card-link {{
            display: block;
            text-decoration: none;
            color: inherit;
            margin-bottom: 18px;
        }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 22px 24px;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            cursor: pointer;
        }}
        .card-link:hover .card {{
            background: var(--card-hover);
            border-color: var(--border-hover);
            transform: translateY(-3px);
            box-shadow: 0 8px 24px rgba(0,0,0,0.45);
        }}
        .card-header-meta {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }}
        .card-source {{
            font-size: 0.8rem;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            background: rgba(56, 189, 248, 0.15);
            color: #38bdf8;
            padding: 5px 12px;
            border-radius: 6px;
            border: 1px solid rgba(56, 189, 248, 0.3);
        }}
        .badge-new {{
            font-size: 0.75rem;
            font-weight: 800;
            background: var(--accent-green);
            color: #080c14;
            padding: 4px 10px;
            border-radius: 6px;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            box-shadow: 0 0 10px rgba(16, 185, 129, 0.4);
        }}
        .cve-badge {{
            display: inline-block;
            font-size: 0.85rem;
            font-weight: 800;
            background: rgba(244, 63, 94, 0.2);
            color: #f43f5e;
            padding: 3px 10px;
            border-radius: 6px;
            border: 1px solid rgba(244, 63, 94, 0.4);
            margin: 0 2px;
            transition: all 0.2s;
        }}
        .cve-badge:hover {{
            background: #f43f5e;
            color: #ffffff;
        }}
        .card-title {{
            color: var(--text-main);
            font-weight: 800;
            font-size: 1.25rem;
            line-height: 1.4;
            display: block;
            margin-bottom: 12px;
            transition: color 0.2s ease;
        }}
        .card-link:hover .card-title {{
            color: var(--accent-blue);
        }}
        .card-desc {{
            font-size: 1.15rem;
            color: var(--text-sub);
            margin: 0;
            line-height: 1.65;
            font-weight: 400;
        }}
        .ok-box {{
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: var(--accent-green);
            padding: 18px 22px;
            border-radius: 12px;
            font-size: 1.05rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 40px;
            padding: 16px;
            border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <div class="pulse-dot"></div>
                <h1>Cyber Security Dashboard</h1>
            </div>
            <span class="badge-time">Actualizat: {now_str}</span>
        </header>

        <!-- STATS COUNTERS BAR -->
        <div class="stats-grid">
            <div class="stat-card stat-red" onclick="switchTab('targeted')">
                <div>
                    <div class="stat-lbl">Specifice</div>
                    <div class="stat-val">{count_targeted}</div>
                </div>
                <div>🔴</div>
            </div>
            <div class="stat-card stat-orange" onclick="switchTab('critical')">
                <div>
                    <div class="stat-lbl">Threat Intel</div>
                    <div class="stat-val">{count_critical}</div>
                </div>
                <div>🟠</div>
            </div>
            <div class="stat-card stat-blue" onclick="switchTab('general')">
                <div>
                    <div class="stat-lbl">Generale</div>
                    <div class="stat-val">{count_gen}</div>
                </div>
                <div>🔵</div>
            </div>
            <div class="stat-card stat-total" onclick="switchTab('all')">
                <div>
                    <div class="stat-lbl">Total Monitorizate</div>
                    <div class="stat-val">{count_total}</div>
                </div>
                <div>📊</div>
            </div>
        </div>

        <!-- SEARCH & FILTER PANELS -->
        <div class="controls-panel">
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="🔍 Caută vulnerabilitate, serviciu sau CVE (ex: joomla, cpanel, rce, CVE-2026)..." onkeyup="filterCards()">
            </div>
            <div class="tabs-row">
                <button class="tab-btn active" id="tab-btn-all" onclick="switchTab('all')">Toate ({count_total})</button>
                <button class="tab-btn" id="tab-btn-targeted" onclick="switchTab('targeted')">🔴 Specifice ({count_targeted})</button>
                <button class="tab-btn" id="tab-btn-critical" onclick="switchTab('critical')">🟠 Threat Intel ({count_critical})</button>
                <button class="tab-btn" id="tab-btn-general" onclick="switchTab('general')">🔵 Generale ({count_gen})</button>
            </div>
        </div>
    """

    # ALERTE SPECIFICE
    if targeted_news:
        html_out += '<div class="section-title title-red" data-section="targeted">🔴 Alerte Specifice (Joomla / PHP / Web / Mail)</div>'
        for item in targeted_news:
            new_badge_html = '<span class="badge-new">NOU</span>' if item["is_new"] else ''
            title_formatted = format_cve(item['title'])
            summary_formatted = format_cve(item['summary'])
            html_out += f"""
            <a href="{item['link']}" target="_blank" class="card-link" data-category="targeted">
                <div class="card">
                    <div class="card-header-meta">
                        <span class="card-source">{item['source']}</span>
                        {new_badge_html}
                    </div>
                    <span class="card-title">{title_formatted}</span>
                    <p class="card-desc">{summary_formatted}</p>
                </div>
            </a>
            """
    else:
        html_out += '<div class="ok-box" data-category="targeted">✅ Nicio alertă critică directă detectată pentru Joomla, PHP sau serverul web în ultimele 36 ore.</div>'

    # THREAT INTEL
    if critical_news:
        html_out += '<div class="section-title title-orange" data-section="critical">🟠 Threat Intelligence & 0-Day / RCE</div>'
        for item in critical_news[:12]:
            new_badge_html = '<span class="badge-new">NOU</span>' if item["is_new"] else ''
            title_formatted = format_cve(item['title'])
            summary_formatted = format_cve(item['summary'])
            html_out += f"""
            <a href="{item['link']}" target="_blank" class="card-link" data-category="critical">
                <div class="card">
                    <div class="card-header-meta">
                        <span class="card-source">{item['source']}</span>
                        {new_badge_html}
                    </div>
                    <span class="card-title">{title_formatted}</span>
                    <p class="card-desc">{summary_formatted}</p>
                </div>
            </a>
            """

    # GENERAL
    if gen_news:
        html_out += '<div class="section-title title-blue" data-section="general">🔵 Știri & Fluxuri Global Security</div>'
        for item in gen_news[:15]:
            new_badge_html = '<span class="badge-new">NOU</span>' if item["is_new"] else ''
            title_formatted = format_cve(item['title'])
            html_out += f"""
            <a href="{item['link']}" target="_blank" class="card-link" data-category="general">
                <div class="card">
                    <div class="card-header-meta">
                        <span class="card-source">{item['source']}</span>
                        {new_badge_html}
                    </div>
                    <span class="card-title">{title_formatted}</span>
                </div>
            </a>
            """

    html_out += """
        <footer>Cyber Digest Monitoring System</footer>
    </div>

    <!-- FRONTEND FILTERING SCRIPT -->
    <script>
        let currentTab = 'all';

        function switchTab(category) {
            currentTab = category;
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            const activeBtn = document.getElementById('tab-btn-' + category);
            if(activeBtn) activeBtn.classList.add('active');
            filterCards();
        }

        function filterCards() {
            const query = document.getElementById('searchInput').value.toLowerCase().trim();
            const cardLinks = document.querySelectorAll('.card-link');

            cardLinks.forEach(cardLink => {
                const matchesCategory = (currentTab === 'all') || (cardLink.getAttribute('data-category') === currentTab);
                const text = cardLink.innerText.toLowerCase();
                const matchesSearch = !query || text.includes(query);

                if (matchesCategory && matchesSearch) {
                    cardLink.style.display = 'block';
                } else {
                    cardLink.style.display = 'none';
                }
            });
        }
    </script>
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
    print("index.html generat cu succes.")

    current_utc_hour = datetime.now(timezone.utc).hour
    force_email = os.environ.get("FORCE_EMAIL", "false").lower() == "true"
    
    if current_utc_hour == 5 or force_email:
        send_email(f"🛡️ Daily Cyber Digest - {datetime.now().strftime('%d.%m.%Y')}", html_dashboard)
