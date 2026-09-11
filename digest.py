#!/usr/bin/env python3
"""
Cyber Security Monitoring & Alerting Engine (v2.2 - Merged Bugfix)
--------------------------------------------------------------------
- Trage feed-uri RSS/Atom de securitate în paralel (ThreadPoolExecutor).
- Extragere robustă ElementTree (verificare explicită `is not None`).
- Filtrează și clasifică articolele din ultimele 36 ore (Targeted, Critical, General).
- Generare Dashboard HTML interactiv (dark theme, live search, filtrare, auto-link CVE-uri).
- Toate datele/orele sunt afișate în Ora României (Europe/Bucharest - EET/EEST).
- Trimitere raport zilnic prin email (SMTP TLS/SSL, Text+HTML) la ora 08:00 (Ora RO) sau via FORCE_EMAIL.

ISTORIC MODIFICĂRI (comentarii marcate cu # FIX):
1. BUG CRITIC (v2.0→v2.1): `item.find(x) or item.find(y)` folosea truth-value
   pe obiecte xml.etree.ElementTree.Element, determinat de NUMĂRUL DE COPII,
   nu de existența elementului. Un <title>Text</title> obișnuit (fără copii)
   evalua la False chiar dacă exista → pierdere silențioasă de titlu/link/
   descriere/dată pentru majoritatea feed-urilor RSS standard. Corectat cu
   first_not_none() (verificare explicită `is not None`).
2. BUG (v2.1→v2.2): pentru articolele cu dată ilizibilă, `date` era setată la
   `now_utc`, ceea ce făcea ca `is_new` să fie mereu True (diferență ~0) —
   badge „NOU" fals-pozitiv pe articole de vârstă necunoscută. Corectat:
   `date_unknown` separat de `is_new`, care e explicit False când data nu se
   cunoaște; dashboard afișează „Data necunoscută" în loc de o oră înșelătoare.
3. Link-ul destinației (href) nu era html.escape()-uit la inserarea în
   atributul HTML → un link cu ghilimele din feed extern putea rupe structura
   atributului. Corectat.
4. Extragerea link-ului verifică explicit `.text.strip()` înainte de fallback
   pe atributul `href` (Atom), evitând link-uri whitespace-only.
5. Excepțiile din fetch_single_feed nu mai sunt silențioase — logate cu numele
   sursei și tipul erorii.
6. Deduplicare articole după link (păstrată din varianta cu dedup — previne
   dubluri din feed-uri RSS/Atom mixte sau republicări).
7. email_to.split(",") face acum strip() pe fiecare adresă — evită respingeri
   SMTP din cauza spațiilor.
8. Corp de email cu alternativă text-plain (reduce riscul de scor spam).
9. Validare explicită a schemei URL pentru link-urile extrase din feed
   (doar http/https acceptate) — plasă de siguranță împotriva unui feed
   compromis care ar injecta scheme precum `javascript:` sau `data:` în href.
10. Eliminat parametrul nefolosit `html_content` din html_to_plain_text()
    (nu era un bug de runtime — apelul pozițional era corect — dar parametrul
    mort era o sursă de confuzie la refactoring viitor).
11. Protecție XML Entity Expansion / "Billion Laughs": folosește
    defusedxml.ElementTree când e disponibil (fallback documentat pe stdlib,
    cu avertisment explicit la pornire dacă pachetul lipsește).
12. Scrierea index.html are fallback reactiv (try/except pe scrierea reală,
    nu doar verificare proactivă cu os.access — testat: os.access() poate
    raporta fals "scriabil" pe o montare read-only cu permisiuni 755).
13. Calea reală a dashboard-ului e propagată explicit prin return/parametru
    (build_web_dashboard() -> send_email(categorized, html_file_path)),
    fără variabilă globală mutabilă — mai testabil, fără stare implicită.
14. Fallback pe tempfile.gettempdir() în loc de "/tmp" hardcodat — portabil
    și pe Windows.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import html
import os
import re
import smtplib
import tempfile
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import urllib.parse
import urllib.request

# FIX (securitate XML): xml.etree.ElementTree standard e vulnerabil teoretic la
# atacuri de tip "Billion Laughs" / entity expansion dacă un feed extern
# conține un DTD cu entități imbricate. defusedxml.ElementTree oferă aceeași
# API dar respinge DTD-urile și entitățile externe. Fallback pe stdlib dacă
# pachetul nu e instalat — mai puțin sigur, dar aplicația rămâne funcțională.
try:
    import defusedxml.ElementTree as ET
    _XML_HARDENED = True
except ImportError:
    import xml.etree.ElementTree as ET
    _XML_HARDENED = False

from zoneinfo import ZoneInfo

# Timezone local pentru România
TZ_RO = ZoneInfo("Europe/Bucharest")

ATOM_NS = "{http://www.w3.org/2005/Atom}"

# ==========================================
# 1. CONFIGURARE SURSE ȘI CUVINTE CHEIE
# ==========================================

RSS_SOURCES = [
    # Surse Naționale & Oficiale
    {"name": "DNSC - Alerte", "url": "https://dnsc.ro/rss/alerte.xml"},
    {"name": "DNSC - Știri", "url": "https://dnsc.ro/rss/stiri.xml"},
    {"name": "CISA - Cybersecurity Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"name": "NVD NIST - Recent CVEs", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml"},
    {"name": "US-CERT - Current Activity", "url": "https://www.cisa.gov/uscert/ncas/current-activity.xml"},
    # Threat Intelligence & Stiri Securitate
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "SANS ISC StormCast", "url": "https://isc.sans.edu/rssfeed.xml"},
    {"name": "KrebsonSecurity", "url": "http://feeds.feedburner.com/krebsonsecurity"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
    {"name": "Trend Micro - Security News", "url": "https://newsroom.trendmicro.com/rss"},
    {"name": "Sophos News", "url": "https://news.sophos.com/en-us/feed/"},
    {"name": "Kaspersky Securelist", "url": "https://securelist.com/feed/"},
    # Platforme Web & Tehnologii Direct Vizate
    {"name": "Joomla Community News", "url": "https://community.joomla.org/blogs.feed?type=rss"},
    {"name": "Joomla Security Announcements", "url": "https://developer.joomla.org/security-centre.feed?type=rss"},
    {"name": "PHP.net News", "url": "https://www.php.net/news.rss"},
    {"name": "cPanel News", "url": "https://news.cpanel.com/feed/"},
    {"name": "Microsoft Security Response (MSRC)", "url": "https://api.msrc.microsoft.com/update-guide/rss"},
]

# Reguli de Clasificare
KEYWORDS_TARGETED = [
    "joomla", "php", "cpanel", "apache", ".htaccess", "mysql", "mariadb",
    "exim", "roundcube", "bind", "named", "mod_security", "whm"
]

KEYWORDS_CRITICAL = [
    "rce", "remote code execution", "zero-day", "0-day", "unauthenticated",
    "critical", "sql injection", "sqli", "privilege escalation", "ransomware",
    "active exploitation", "exploited in the wild", "cvss 9", "cvss 10"
]

KEYWORDS_GENERAL = [
    "cve-", "vulnerability", "patch", "bypass", "malware", "phishing",
    "xss", "cross-site scripting", "denial of service", "dos", "ddos"
]

HOURS_LOOKBACK = 36
MAX_THREADS = 12
REQUEST_TIMEOUT = 10

# ==========================================
# 2. COLECTARE ȘI PARSARE RSS
# ==========================================

def first_not_none(*elements):
    """Returnează primul element XML care nu este None.

    # FIX: înlocuiește pattern-ul `find(x) or find(y)`, care e greșit pentru
    # obiecte ElementTree.Element (truth-value = are copii, nu = există).
    """
    for e in elements:
        if e is not None:
            return e
    return None


ALLOWED_URL_SCHEMES = {"http", "https"}


def is_safe_url(url):
    """Acceptă doar URL-uri http/https. Respinge scheme precum javascript:,
    data:, vbscript: etc. care ar putea fi injectate dintr-un feed compromis.
    """
    if not url or url == "#":
        return False
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    return parsed.scheme.lower() in ALLOWED_URL_SCHEMES and bool(parsed.netloc)


def parse_pub_date(date_str):
    """Încearcă parsarea diverselor formate de dată din RSS/Atom și returnează un datetime conștient de fus/UTC."""
    if not date_str:
        return None

    formats = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S GMT",
        "%a, %d %b %Y %H:%M:%S UTC",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%a, %d %b %Y %H:%M:%S",
    ]

    clean_str = re.sub(r'\s+', ' ', date_str).strip()

    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(clean_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except ValueError:
            continue

    return None


def fetch_single_feed(source):
    """Descarcă și parsează un singur feed RSS/Atom."""
    articles = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSecurityMonitor/2.1'
    }

    try:
        req = urllib.request.Request(source['url'], headers=headers)
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            content = response.read()

        root = ET.fromstring(content)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        threshold_time = now_utc - datetime.timedelta(hours=HOURS_LOOKBACK)

        items = root.findall('.//item') or root.findall(f'.//{ATOM_NS}entry')

        for item in items:
            # FIX: is_not_none în loc de `or` — vezi first_not_none()
            title_node = first_not_none(item.find('title'), item.find(f'{ATOM_NS}title'))
            link_node = first_not_none(item.find('link'), item.find(f'{ATOM_NS}link'))
            desc_node = first_not_none(
                item.find('description'),
                item.find(f'{ATOM_NS}summary'),
                item.find(f'{ATOM_NS}content'),
            )
            date_node = first_not_none(
                item.find('pubDate'),
                item.find(f'{ATOM_NS}published'),
                item.find(f'{ATOM_NS}updated'),
            )

            title = title_node.text.strip() if title_node is not None and title_node.text else "Fără titlu"

            # FIX: verificare explicită .text.strip() înainte de fallback pe href
            # (Atom <link href="..."/> nu are text; RSS <link>text</link> uneori are text whitespace-only)
            link = "#"
            if link_node is not None:
                if link_node.text and link_node.text.strip():
                    link = link_node.text.strip()
                elif 'href' in link_node.attrib:
                    link = link_node.attrib['href'].strip()

            # FIX: acceptăm doar http/https — respinge scheme periculoase dintr-un feed compromis
            if not is_safe_url(link):
                link = "#"

            description = desc_node.text if desc_node is not None and desc_node.text else ""
            clean_desc = re.sub(r'<[^<]+?>', '', description)[:300] + "..." if description else ""

            pub_date_str = date_node.text if date_node is not None else None
            pub_dt = parse_pub_date(pub_date_str) if pub_date_str else None

            # FIX: separă explicit "dată necunoscută" de "dată veche" — nu tratăm
            # articolele nedatate ca fiind recente (vezi is_new mai jos)
            date_unknown = pub_dt is None
            if not date_unknown and pub_dt < threshold_time:
                continue

            articles.append({
                'source': source['name'],
                'title': title,
                'link': link,
                'description': clean_desc,
                'date': pub_dt or now_utc,
                'raw_date': pub_date_str or "Recent",
                'date_unknown': date_unknown,
            })

    except Exception as e:
        # FIX: eroarea nu mai e complet silențioasă — vizibilă în consolă/log
        print(f"[!] Eroare la sursa '{source['name']}' ({source['url']}): {type(e).__name__}: {e}")

    return articles


def fetch_and_filter():
    """Rulează colectarea paralelă și clasifică alertele."""
    all_articles = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_src = {executor.submit(fetch_single_feed, src): src for src in RSS_SOURCES}
        for future in as_completed(future_to_src):
            src = future_to_src[future]
            try:
                data = future.result()
                all_articles.extend(data)
            except Exception as e:
                print(f"[!] Eroare neașteptată la procesarea sursei '{src['name']}': {e}")

    # FIX: deduplicare după link (același articol poate apărea de mai multe ori,
    # de ex. dacă un feed conține atât <link> cât și un id Atom identic după normalizare)
    seen_links = set()
    deduped = []
    for art in all_articles:
        key = art['link'] if art['link'] != '#' else (art['source'], art['title'])
        if key in seen_links:
            continue
        seen_links.add(key)
        deduped.append(art)

    categorized = {
        'targeted': [],
        'critical': [],
        'general': []
    }

    now_utc = datetime.datetime.now(datetime.timezone.utc)

    for art in deduped:
        text_to_scan = f"{art['title']} {art['description']}".lower()

        # FIX: nu marca drept "NOU" un articol a cărui dată reală nu o cunoaștem
        # (altfel, cu date=now_utc ca fallback, diferența e mereu ~0 -> fals-pozitiv)
        if art['date_unknown']:
            art['is_new'] = False
        else:
            art['is_new'] = (now_utc - art['date']).total_seconds() <= 21600

        if any(kw in text_to_scan for kw in KEYWORDS_TARGETED):
            categorized['targeted'].append(art)
        elif any(kw in text_to_scan for kw in KEYWORDS_CRITICAL):
            categorized['critical'].append(art)
        elif any(kw in text_to_scan for kw in KEYWORDS_GENERAL):
            categorized['general'].append(art)

    for cat in categorized:
        categorized[cat].sort(key=lambda x: x['date'], reverse=True)

    return categorized

# ==========================================
# 3. GENERARE DASHBOARD HTML
# ==========================================

def format_cve(text):
    """Transformă mențiunile CVE-YYYY-XXXX în badge-uri cu link direct către NVD NIST."""
    pattern = r'(CVE-\d{4}-\d{4,7})'
    replacement = r'<a href="https://nvd.nist.gov/vuln/detail/\1" target="_blank" class="cve-badge">\1</a>'
    return re.sub(pattern, replacement, html.escape(text), flags=re.IGNORECASE)


def generate_cards_html(articles, category_class):
    if not articles:
        return '<p class="no-data">Nicio alertă detectată în ultimele 36 de ore pentru această categorie.</p>'

    cards = []
    for art in articles:
        new_badge = '<span class="badge badge-new">NOU</span>' if art['is_new'] else ''
        title_formatted = format_cve(art['title'])
        desc_formatted = html.escape(art['description'])

        # FIX: "Data necunoscută" în loc de ora curentă — nu sugerăm o dată falsă
        if art['date_unknown']:
            date_str = "Data necunoscută"
        else:
            date_ro = art['date'].astimezone(TZ_RO)
            date_str = date_ro.strftime('%d %b %Y, %H:%M')

        card = f"""
        <div class="card {category_class}">
            <div class="card-header">
                <span class="source-tag">{html.escape(art['source'])}</span>
                <span class="date-tag">{date_str}</span>
                {new_badge}
            </div>
            <h3 class="card-title"><a href="{html.escape(art['link'])}" target="_blank" rel="noopener">{title_formatted}</a></h3>
            <p class="card-desc">{desc_formatted}</p>
        </div>
        """
        cards.append(card)
    return "\n".join(cards)


def build_web_dashboard(categorized):
    # Generare timestamp în Ora României
    now_ro_str = datetime.datetime.now(TZ_RO).strftime('%d %b %Y, %H:%M (Ora RO)')

    total_targeted = len(categorized['targeted'])
    total_critical = len(categorized['critical'])
    total_general = len(categorized['general'])
    total_all = total_targeted + total_critical + total_general

    html_content = f"""<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Security Intelligence Dashboard</title>
    <style>
        :root {{
            --bg-dark: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-targeted: #f59e0b;
            --accent-critical: #ef4444;
            --accent-general: #3b82f6;
            --border-color: #334155;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            padding: 20px;
            line-height: 1.5;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 25px;
            flex-wrap: wrap;
            gap: 15px;
        }}
        h1 {{ font-size: 1.8rem; font-weight: 700; color: #fff; }}
        .last-update {{ color: var(--text-muted); font-size: 0.9rem; }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .stat-card {{
            background: var(--card-bg);
            padding: 15px 20px;
            border-radius: 8px;
            border-left: 4px solid var(--border-color);
        }}
        .stat-card.targeted {{ border-left-color: var(--accent-targeted); }}
        .stat-card.critical {{ border-left-color: var(--accent-critical); }}
        .stat-card.general {{ border-left-color: var(--accent-general); }}
        .stat-value {{ font-size: 1.8rem; font-weight: bold; margin-top: 5px; }}
        .stat-label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; }}

        .controls {{
            display: flex;
            gap: 15px;
            margin-bottom: 25px;
            flex-wrap: wrap;
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
            padding: 10px 15px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: #fff;
            font-size: 0.95rem;
        }}
        .search-box:focus {{ outline: 2px solid var(--accent-general); }}
        .tabs {{ display: flex; gap: 8px; }}
        .tab-btn {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
        }}
        .tab-btn.active {{
            background: var(--accent-general);
            border-color: var(--accent-general);
            color: #fff;
        }}

        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
            gap: 20px;
        }}
        .card {{
            background: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            border: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }}
        .card.targeted-card {{ border-top: 3px solid var(--accent-targeted); }}
        .card.critical-card {{ border-top: 3px solid var(--accent-critical); }}
        .card.general-card {{ border-top: 3px solid var(--accent-general); }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.8rem;
            margin-bottom: 12px;
            gap: 5px;
        }}
        .source-tag {{ color: var(--text-muted); font-weight: 600; }}
        .date-tag {{ color: var(--text-muted); }}
        .badge {{
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.7rem;
        }}
        .badge-new {{ background: #10b981; color: #fff; }}
        .cve-badge {{
            background: #334155;
            color: #38bdf8;
            padding: 2px 6px;
            border-radius: 4px;
            text-decoration: none;
            font-size: 0.85rem;
            font-family: monospace;
        }}
        .cve-badge:hover {{ background: #475569; }}
        .card-title {{
            font-size: 1.1rem;
            margin-bottom: 10px;
            line-height: 1.3;
        }}
        .card-title a {{ color: #fff; text-decoration: none; }}
        .card-title a:hover {{ color: var(--accent-general); }}
        .card-desc {{
            color: var(--text-muted);
            font-size: 0.9rem;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }}
        .no-data {{ color: var(--text-muted); grid-column: 1 / -1; padding: 40px; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Cyber Security Intelligence</h1>
                <p class="last-update">Sincronizat la: {now_ro_str}</p>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Alerte</div>
                <div class="stat-value">{total_all}</div>
            </div>
            <div class="stat-card targeted">
                <div class="stat-label">Infrastructură Vizată</div>
                <div class="stat-value" style="color: var(--accent-targeted);">{total_targeted}</div>
            </div>
            <div class="stat-card critical">
                <div class="stat-label">Alerte Critice / Threat Intel</div>
                <div class="stat-value" style="color: var(--accent-critical);">{total_critical}</div>
            </div>
            <div class="stat-card general">
                <div class="stat-label">Alerte Generale Vulnerabilități</div>
                <div class="stat-value" style="color: var(--accent-general);">{total_general}</div>
            </div>
        </div>

        <div class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Căutare după termen sau CVE (ex: Joomla, RCE, CVE-2026)..." onkeyup="filterCards()">
            <div class="tabs">
                <button class="tab-btn active" onclick="filterCategory('all', this)">Toate</button>
                <button class="tab-btn" onclick="filterCategory('targeted-card', this)">Vizate</button>
                <button class="tab-btn" onclick="filterCategory('critical-card', this)">Critice</button>
                <button class="tab-btn" onclick="filterCategory('general-card', this)">Generale</button>
            </div>
        </div>

        <div class="cards-grid" id="cardsGrid">
            {generate_cards_html(categorized['targeted'], 'targeted-card')}
            {generate_cards_html(categorized['critical'], 'critical-card')}
            {generate_cards_html(categorized['general'], 'general-card')}
        </div>
    </div>

    <script>
        let currentCategory = 'all';

        function filterCategory(cat, btn) {{
            currentCategory = cat;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterCards();
        }}

        function filterCards() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const cards = document.querySelectorAll('.card');

            cards.forEach(card => {{
                const text = card.innerText.toLowerCase();
                const matchesSearch = text.includes(query);
                const matchesCategory = (currentCategory === 'all') || card.classList.contains(currentCategory);

                if (matchesSearch && matchesCategory) {{
                    card.style.display = 'flex';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>"""

    return write_dashboard_file(html_content)


def write_dashboard_file(html_content, filename="index.html"):
    """Scrie dashboard-ul HTML și returnează calea unde a fost scris efectiv.

    # FIX: fallback reactiv (try/except pe scrierea reală), nu doar verificare
    # proactivă cu os.access() — os.access() verifică doar biții de permisiune
    # și NU detectează montări read-only cu permisiuni aparent OK, disc plin,
    # sau atribute immutable. Testat: os.access() poate raporta "scriabil" în
    # timp ce scrierea reală eșuează — de aceea încercăm scrierea efectivă și
    # reacționăm la eșec, nu doar verificăm în avans.
    # FIX: tempfile.gettempdir() în loc de "/tmp" hardcodat — portabil și pe
    # Windows, unde /tmp nu există.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filename
    except OSError as e:
        fallback_path = os.path.join(tempfile.gettempdir(), filename)
        print(f"[!] Nu s-a putut scrie {filename} în directorul curent ({e}). "
              f"Se încearcă fallback pe {fallback_path}.")
        with open(fallback_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[+] Dashboard scris cu succes în {fallback_path}.")
        return fallback_path

# ==========================================
# 4. MODUL NOTIFICARE EMAIL
# ==========================================

def html_to_plain_text(categorized):
    """Generează un corp de email text-plain simplu, pe baza datelor structurate
    (nu prin parsare HTML) — evită dependențe suplimentare și reduce riscul de spam-score.
    """
    lines = ["RAPORT ZILNIC CYBER SECURITY INTELLIGENCE", "=" * 45, ""]
    for label, key in [("INFRASTRUCTURĂ VIZATĂ", "targeted"),
                        ("ALERTE CRITICE", "critical"),
                        ("ALERTE GENERALE", "general")]:
        lines.append(f"-- {label} ({len(categorized[key])}) --")
        if not categorized[key]:
            lines.append("  (nicio alertă în ultimele 36h)")
        for art in categorized[key]:
            date_ro = art['date'].astimezone(TZ_RO).strftime('%d %b %Y, %H:%M')
            lines.append(f"  [{art['source']}] {art['title']} ({date_ro})")
            lines.append(f"    {art['link']}")
        lines.append("")
    return "\n".join(lines)


def send_email(categorized, html_file_path):
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_to_raw = os.getenv("EMAIL_TO")

    if not all([smtp_server, smtp_user, smtp_password, email_to_raw]):
        print("[!] Variabilele de mediu SMTP nu sunt complet configurate. Email-ul nu a fost trimis.")
        return

    # FIX: strip() pe fiecare adresă — evita respingeri SMTP din cauza spațiilor
    email_to_list = [addr.strip() for addr in email_to_raw.split(",") if addr.strip()]
    if not email_to_list:
        print("[!] EMAIL_TO nu conține nicio adresă validă. Email-ul nu a fost trimis.")
        return

    now_ro_str = datetime.datetime.now(TZ_RO).strftime('%d %b %Y')

    msg = MIMEMultipart("alternative")
    msg['Subject'] = Header(f"Raport Zilnic Cyber Security Intelligence - {now_ro_str}", "utf-8")
    msg['From'] = smtp_user
    msg['To'] = ", ".join(email_to_list)

    try:
        with open(html_file_path, "r", encoding="utf-8") as f:
            html_body = f.read()
    except Exception as e:
        print(f"[!] Eroare la citirea index.html pentru email: {e}")
        return

    # FIX: alternativă text-plain — MIME best practice, reduce riscul de spam
    # (parametrul html_content nemaifolosit a fost eliminat din semnătură)
    plain_body = html_to_plain_text(categorized)
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=15) as server:
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, email_to_list, msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, email_to_list, msg.as_string())
        print("[+] Notificarea pe email a fost trimisă cu succes.")
    except Exception as e:
        print(f"[!] Eroare la trimiterea email-ului: {e}")

# ==========================================
# 5. PUNCT PRINCIPAL DE EXECUȚIE
# ==========================================

if __name__ == "__main__":
    if not _XML_HARDENED:
        print("[!] ATENȚIE: pachetul 'defusedxml' nu este instalat — se folosește "
              "xml.etree.ElementTree standard, vulnerabil teoretic la atacuri de "
              "tip entity expansion pe feed-uri XML compromise. Recomandat: "
              "pip install defusedxml")

    print("[*] Colectare și filtrare alerte din sursele RSS...")
    categorized_data = fetch_and_filter()

    print("[*] Generare Dashboard HTML...")
    saved_path = build_web_dashboard(categorized_data)
    print(f"[+] Dashboard generat cu succes la: {saved_path}")

    now_ro = datetime.datetime.now(TZ_RO)
    force_email = os.getenv("FORCE_EMAIL", "false").lower() == "true"

    if now_ro.hour == 8 or force_email:
        print("[*] Se inițiază trimiterea email-ului...")
        send_email(categorized_data, saved_path)
    else:
        print(f"[*] Email-ul nu a fost trimis (Ora locală RO: {now_ro.strftime('%H:%M')}; Programat la: 08:00 RO). Pentru forțare, setați FORCE_EMAIL=true.")
