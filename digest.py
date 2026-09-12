#!/usr/bin/env python3
"""
Cyber Security Monitoring & Intelligence Engine (v4.6 - Mobile-Bulletproof Enterprise Edition)
-----------------------------------------------------------------------------------------
- Integrare completă a celor 31 de surse RSS/Atom de securitate cu priorități ponderate.
- Securizare XML defensivă (defusedxml + expat DOCTYPE rejection).
- Protecție SSRF robustă (validare URL, blocare IP-uri private, loopback, link-local).
- Cache HTTP inteligent cu ETag/Last-Modified și bypass automat la rulare manuală (workflow_dispatch).
- Parser de date avansat cu suport extins pentru fusuri orare și abrevieri.
- Extracție IOC avansată (CVE-uri și adrese IPv4) și motor de scorare corectat pentru infrastructură.
- Scriere atomică sigură pentru cache și dashboard HTML.
- DOUĂ ieșiri HTML separate și independente:
    1) build_web_dashboard()   -> index.html, servit pe GitHub Pages (CSS Grid/Flexbox/var(), OK pt. browser)
    2) build_mobile_email_html() -> corp de email dedicat, layout single-column stivuit,
       fără CSS Grid/Flexbox/variabile CSS (nesuportate de clienții de mail), fără colspan.
  Motivul separării: trimiterea DIRECTĂ a index.html ca și corp de email (cum se întâmpla în
  v4.2) produce randare stricată pe mobil, pentru că Gmail/Outlook nu suportă var(), grid sau
  flex — proprietățile cad silențios și layout-ul se prăbușește la comportamentul default block/inline.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import datetime
import html
import ipaddress
import json
import os
import re
import smtplib
import ssl
import tempfile
import time
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import urllib.error
import urllib.parse
import urllib.request

try:
    import defusedxml.ElementTree as ET
    _XML_HARDENED = True
except ImportError:
    import xml.etree.ElementTree as ET
    import xml.parsers.expat
    _XML_HARDENED = False

    class DoctypeRejectedError(ValueError):
        """Ridicată când un feed XML conține o declarație DOCTYPE."""
        pass

    def _reject_doctype_if_present(content_bytes):
        parser = xml.parsers.expat.ParserCreate()
        def _on_doctype(*args, **kwargs):
            raise DoctypeRejectedError("Feed XML respins: conține DOCTYPE — posibil atac entity expansion.")
        parser.StartDoctypeDeclHandler = _on_doctype
        parser.Parse(content_bytes, True)

    _original_et_fromstring = ET.fromstring
    def _hardened_fromstring(content_bytes):
        _reject_doctype_if_present(content_bytes)
        return _original_et_fromstring(content_bytes)
    ET.fromstring = _hardened_fromstring

from zoneinfo import ZoneInfo

TZ_RO = ZoneInfo("Europe/Bucharest")
ATOM_NS = "{http://www.w3.org/2005/Atom}"

# ==========================================
# CONFIGURARE CELE 31 SURSE ȘI PRIORITĂȚI
# ==========================================

RSS_SOURCES = [
    # Surse Naționale & Oficiale / Guvernamentale
    {"name": "DNSC - Alerte", "url": "https://dnsc.ro/rss/alerte.xml", "priority": 95},
    {"name": "DNSC - Știri", "url": "https://dnsc.ro/rss/stiri.xml", "priority": 90},
    {"name": "CISA - Cybersecurity Advisories", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml", "priority": 100},
    {"name": "CISA - Current Activity", "url": "https://www.cisa.gov/uscert/ncas/current-activity.xml", "priority": 100},
    {"name": "NVD NIST - Recent CVEs", "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "priority": 95},

    # Threat Intelligence & Știri Securitate Enterprise
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "priority": 75},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "priority": 75},
    {"name": "Krebs on Security", "url": "http://feeds.feedburner.com/krebsonsecurity", "priority": 80},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "priority": 70},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "priority": 65},
    {"name": "Ars Technica - Security", "url": "https://arstechnica.com/security/feed/", "priority": 70},
    {"name": "SANS ISC StormCast", "url": "https://isc.sans.edu/rssfeed.xml", "priority": 85},
    {"name": "Trend Micro - Security News", "url": "https://newsroom.trendmicro.com/rss", "priority": 75},
    {"name": "Sophos News", "url": "https://news.sophos.com/en-us/feed/", "priority": 75},
    {"name": "Kaspersky Securelist", "url": "https://securelist.com/feed/", "priority": 80},

    # Windows și Ecosistemul Microsoft
    {"name": "Microsoft Security Response (MSRC)", "url": "https://api.msrc.microsoft.com/update-guide/rss", "priority": 95},
    {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/", "priority": 85},
    {"name": "Windows IT Pro Blog", "url": "https://techcommunity.microsoft.com/t5/windows-it-pro-blog/bg-p/WindowsITProBlog/rss", "priority": 70},

    # Android și Securitate Mobilă
    {"name": "Google Online Security Blog", "url": "https://security.googleblog.com/feeds/posts/default", "priority": 85},
    {"name": "Android Police - News", "url": "https://www.androidpolice.com/feed/", "priority": 60},
    {"name": "Android Authority", "url": "https://www.androidauthority.com/feed/", "priority": 60},

    # Hardware Hacks și Securitate Low-Level / Embedded
    {"name": "Hackaday", "url": "https://hackaday.com/feed/", "priority": 65},
    {"name": "Tom's Hardware", "url": "https://www.tomshardware.com/feeds/all", "priority": 60},
    {"name": "IEEE Spectrum", "url": "https://spectrum.ieee.org/rss/fulltext", "priority": 65},
    {"name": "Phoronix", "url": "https://www.phoronix.com/rss.php", "priority": 60},

    # Platforme Web & Tehnologii Direct Vizate
    {"name": "Joomla Community News", "url": "https://community.joomla.org/blogs.feed?type=rss", "priority": 90},
    {"name": "Joomla Security Announcements", "url": "https://developer.joomla.org/security-centre.feed?type=rss", "priority": 95},
    {"name": "PHP.net News", "url": "https://www.php.net/news.rss", "priority": 90},
    {"name": "cPanel News", "url": "https://news.cpanel.com/feed/", "priority": 90},

    # Suplimentar completare 31 surse active
    {"name": "Cisco Talos Intelligence", "url": "https://blog.talosintelligence.com/rss/", "priority": 85},
    {"name": "CERT-RO / DNSC Blog", "url": "https://dnsc.ro/blog/rss", "priority": 90},
]

SOURCE_PRIORITY_MAP = {src['name']: src['priority'] for src in RSS_SOURCES}

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
    "xss", "cross-site scripting", "denial of service", "dos", "ddos",
    "windows", "patch tuesday", "android", "pixel", "firmware",
    "hardware", "microcode", "side-channel", "spectre", "meltdown", "uefi", "bios"
]

HOURS_LOOKBACK = 36
MAX_THREADS = min(24, max(8, len(RSS_SOURCES)))
REQUEST_TIMEOUT = 10

TZ_ABBR_OFFSETS = {
    'UT': '+0000', 'GMT': '+0000', 'UTC': '+0000', 'Z': '+0000',
    'EST': '-0500', 'EDT': '-0400',
    'CST': '-0600', 'CDT': '-0500',
    'MST': '-0700', 'MDT': '-0600',
    'PST': '-0800', 'PDT': '-0700',
    'BST': '+0100', 'CEST': '+0200', 'CET': '+0100'
}

# ==========================================
# HELPERI: URL, XML, DATE & IOC
# ==========================================

def first_not_none(*nodes):
    for n in nodes:
        if n is not None:
            return n
    return None

def is_safe_url(url):
    if not url or url == "#":
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            return False
        host = (parsed.hostname or "").lower()
        if host == "localhost" or host.endswith(".local"):
            return False
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except ValueError:
            pass
        return True
    except ValueError:
        return False

def normalize_url(url):
    if not is_safe_url(url):
        return "#"
    try:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        filtered_params = [
            (k, v) for k, v in query_params
            if not k.lower().startswith(('utm_', 'fbclid', 'gclid', 'ref', 'source'))
        ]
        normalized_query = urllib.parse.urlencode(filtered_params)
        return urllib.parse.urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            normalized_query,
            ''
        ))
    except Exception:
        return url

def parse_pub_date(date_str):
    if not date_str:
        return None
    clean_str = re.sub(r'\s+', ' ', date_str).strip()
    for abbr, offset in TZ_ABBR_OFFSETS.items():
        if clean_str.endswith(f' {abbr}'):
            clean_str = clean_str[:-len(abbr)] + offset
            break

    formats = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S.%f %z",
        "%a, %d %b %Y %H:%M:%S GMT",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%a, %d %b %Y %H:%M:%S"
    ]
    for fmt in formats:
        try:
            dt = datetime.datetime.strptime(clean_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except ValueError:
            continue
    return None

def contains_keyword(text, keywords):
    for k in keywords:
        if k and not k[0].isalnum():
            pattern = re.escape(k)
        else:
            pattern = r"\b" + re.escape(k) + r"\b"
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False

def extract_iocs(text):
    cves = sorted(list(set(re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE))))
    ips = sorted(list(set(re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text))))
    return {'cves': cves, 'ips': ips}

HTTP_RETRY_ATTEMPTS = 3
HTTP_RETRY_BACKOFF_BASE = 1.5

def _fetch_url_with_retry(url, headers, timeout):
    last_error = None
    for attempt in range(HTTP_RETRY_ATTEMPTS):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.read(), response.headers.get('ETag'), response.headers.get('Last-Modified'), 200
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return b"", None, None, 304
            last_error = e
            if attempt < HTTP_RETRY_ATTEMPTS - 1:
                time.sleep(HTTP_RETRY_BACKOFF_BASE * (attempt + 1))
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_error = e
            if attempt < HTTP_RETRY_ATTEMPTS - 1:
                time.sleep(HTTP_RETRY_BACKOFF_BASE * (attempt + 1))
    raise last_error

def fetch_single_feed(source, http_cache):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSecurityMonitor/4.6'
    }

    cache_entry = http_cache.get(source['url'], {})
    if cache_entry.get('etag'):
        headers['If-None-Match'] = cache_entry['etag']
    if cache_entry.get('last_modified'):
        headers['If-Modified-Since'] = cache_entry['last_modified']

    try:
        content, new_etag, new_last_modified, status_code = _fetch_url_with_retry(source['url'], headers, REQUEST_TIMEOUT)
        if status_code == 304:
            cached_arts = copy.deepcopy(cache_entry.get('cached_articles', []))
            for art in cached_arts:
                date_val = art.get('date')
                if isinstance(date_val, str):
                    try:
                        art['date'] = datetime.datetime.fromisoformat(date_val)
                    except ValueError:
                        pass
                art['date_obj'] = art.get('date')
            return cached_arts
    except Exception as e:
        print(f"[!] Eroare la sursa '{source['name']}': {type(e).__name__}: {e}")
        return []

    articles = []
    try:
        root = ET.fromstring(content)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        threshold_time = now_utc - datetime.timedelta(hours=HOURS_LOOKBACK)

        items = root.findall('.//item') or root.findall(f'.//{ATOM_NS}entry')
        for item in items:
            title_node = first_not_none(item.find('title'), item.find(f'{ATOM_NS}title'))
            link_node = first_not_none(item.find('link'), item.find(f'{ATOM_NS}link'))
            desc_node = first_not_none(item.find('description'), item.find(f'{ATOM_NS}summary'), item.find(f'{ATOM_NS}content'))
            date_node = first_not_none(item.find('pubDate'), item.find(f'{ATOM_NS}published'), item.find(f'{ATOM_NS}updated'))

            title = title_node.text.strip() if title_node is not None and title_node.text else "Fără titlu"
            raw_link = link_node.text.strip() if link_node is not None and link_node.text else (link_node.attrib.get('href', '#') if link_node is not None else '#')
            link = normalize_url(raw_link)

            description = desc_node.text if desc_node is not None and desc_node.text else ""
            clean_desc = html.unescape(re.sub(r'<[^<]+?>', '', description))[:300] + "..." if description else ""

            pub_date_str = date_node.text if date_node is not None else None
            pub_dt = parse_pub_date(pub_date_str) if pub_date_str else None

            date_unknown = pub_dt is None
            if not date_unknown and pub_dt < threshold_time:
                continue

            iocs = extract_iocs(f"{title} {clean_desc}")

            articles.append({
                'source': source['name'],
                'title': title,
                'link': link,
                'description': clean_desc,
                'date': pub_dt.isoformat() if pub_dt else now_utc.isoformat(),
                'date_obj': pub_dt or now_utc,
                'date_unknown': date_unknown,
                'iocs': iocs
            })

        serializable_articles = []
        for art in articles:
            art_copy = art.copy()
            if isinstance(art_copy.get('date'), datetime.datetime):
                art_copy['date'] = art_copy['date'].isoformat()
            if 'date_obj' in art_copy:
                del art_copy['date_obj']
            serializable_articles.append(art_copy)

        http_cache[source['url']] = {
            'etag': new_etag,
            'last_modified': new_last_modified,
            'cached_articles': serializable_articles
        }
    except Exception as e:
        print(f"[!] Eroare parsare XML pentru '{source['name']}': {e}")

    return articles

# ==========================================
# PERSISTENȚĂ CACHE ATOMIC
# ==========================================

CACHE_FILENAME = "security_engine_cache.json"

def load_cache():
    if not os.path.exists(CACHE_FILENAME):
        return {}
    try:
        with open(CACHE_FILENAME, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_cache(cache_data):
    dir_name = os.path.dirname(os.path.abspath(CACHE_FILENAME)) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, text=True)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, CACHE_FILENAME)
    except Exception as e:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        print(f"[!] Eroare salvare atomică cache: {e}")

def fetch_and_filter():
    cache = load_cache()

    # Bypass cache HTTP la rulare manuală (workflow_dispatch) sau forțată
    is_manual_run = (os.getenv("GITHUB_EVENT_NAME") == "workflow_dispatch" or
                     os.getenv("FORCE_REFRESH", "").lower() == "true")

    if is_manual_run:
        print("[*] Rulare manuală detectată (workflow_dispatch): se resetează cache-ul HTTP pentru date proaspete.")
        http_cache = {}
    else:
        http_cache = cache.get('http_cache', {})

    all_articles = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_src = {executor.submit(fetch_single_feed, src, http_cache): src for src in RSS_SOURCES}
        for future in as_completed(future_to_src):
            try:
                res = future.result()
                for art in res:
                    if isinstance(art.get('date'), str):
                        try:
                            art['date'] = datetime.datetime.fromisoformat(art['date'])
                        except ValueError as ve:
                            print(f"[!] Eroare parsare dată ISO pentru articolul '{art.get('title', 'Necunoscut')}': {ve}")
                    if 'date_obj' not in art:
                        art['date_obj'] = art.get('date')
                all_articles.extend(res)
            except Exception as e:
                print(f"[!] Eroare thread feed: {e}")

    seen_links = set()
    deduped = []
    for art in all_articles:
        key = art['link'] if art['link'] != '#' else (art['source'], art['title'])
        if key in seen_links:
            continue
        seen_links.add(key)
        deduped.append(art)

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    first_seen_cache = cache.get('first_seen', {})
    bounded_deduped = []

    for art in deduped:
        cache_key = art['link'] if art['link'] != '#' else f"{art['source']}::{art['title']}"
        if art['date_unknown']:
            first_seen_iso = first_seen_cache.get(cache_key)
            if not first_seen_iso:
                first_seen_cache[cache_key] = now_utc.isoformat()
                bounded_deduped.append(art)
            else:
                try:
                    fs = datetime.datetime.fromisoformat(first_seen_iso)
                    if (now_utc - fs).total_seconds() / 3600 <= HOURS_LOOKBACK:
                        bounded_deduped.append(art)
                except ValueError:
                    bounded_deduped.append(art)
        else:
            if isinstance(art.get('date'), datetime.datetime) and (now_utc - art['date']).total_seconds() / 3600 <= HOURS_LOOKBACK:
                bounded_deduped.append(art)

    cache['first_seen'] = first_seen_cache
    cache['http_cache'] = http_cache
    save_cache(cache)

    categorized = {'targeted': [], 'critical': [], 'general': []}

    for art in bounded_deduped:
        text_to_scan = f"{art['title']} {art['description']}".lower()
        if isinstance(art.get('date'), datetime.datetime):
            art['is_new'] = (now_utc - art['date']).total_seconds() <= 21600
        else:
            art['is_new'] = False

        is_targeted_infra = contains_keyword(text_to_scan, KEYWORDS_TARGETED)
        has_critical = contains_keyword(text_to_scan, KEYWORDS_CRITICAL)
        has_general = contains_keyword(text_to_scan, KEYWORDS_GENERAL)

        score = 0
        if is_targeted_infra:
            score += 30
        if has_general:
            score += 10
        if has_critical:
            score += 70

        cvss_match = re.search(r'(?:cvss(?:\s*v?3\.[01])?|base\s+score)[:\s_v]*([0-9.]+)', text_to_scan, re.IGNORECASE)
        if cvss_match:
            try:
                cvss_val = float(cvss_match.group(1))
                if 0.0 <= cvss_val <= 10.0:
                    score += int(cvss_val * 3)
            except ValueError:
                pass

        if "exploited in the wild" in text_to_scan or "active exploitation" in text_to_scan:
            score += 30

        art['risk_score'] = score
        art['is_targeted_infra'] = is_targeted_infra

        # Logică de categorisire: infrastructura vizată are prioritate maximă
        if is_targeted_infra:
            categorized['targeted'].append(art)
        elif score >= 70:
            categorized['critical'].append(art)
        else:
            categorized['general'].append(art)

    for cat in categorized:
        categorized[cat].sort(key=lambda x: (
            x['risk_score'],
            SOURCE_PRIORITY_MAP.get(x['source'], 50),
            x.get('date', '')
        ), reverse=True)

    return categorized

# ==========================================
# 1) GENERATOR DASHBOARD WEB (GitHub Pages, browser modern — CSS Grid/Flexbox/var() OK aici)
# ==========================================

def format_cve(text):
    pattern = r'(CVE-\d{4}-\d{4,7})'
    replacement = r'<a href="https://nvd.nist.gov/vuln/detail/\1" target="_blank" class="cve-badge">\1</a>'
    return re.sub(pattern, replacement, html.escape(text), flags=re.IGNORECASE)

def generate_cards_html(articles, category_class):
    if not articles:
        return '<p class="no-data">Nicio alertă detectată în intervalul specificat.</p>'

    cards = []
    for art in articles:
        new_badge = '<span class="badge badge-new">NOU</span>' if art['is_new'] else ''
        infra_badge = '<span class="badge badge-infra">INFRA</span>' if art.get('is_targeted_infra') and category_class != 'targeted-card' else ''
        score_badge = f'<span class="badge badge-score">SCORE: {art.get("risk_score", 0)}</span>'

        ioc_html = ""
        if art['iocs']['cves'] or art['iocs']['ips']:
            cve_spans = "".join([f'<span class="ioc-pill">CVE: {c}</span>' for c in art['iocs']['cves'][:3]])
            ip_spans = "".join([f'<span class="ioc-pill">IP: {ip}</span>' for ip in art['iocs']['ips'][:2]])
            ioc_html = f'<div class="ioc-container">{cve_spans}{ip_spans}</div>'

        title_formatted = format_cve(art['title'])
        desc_formatted = html.escape(art['description'])

        art_date = art.get('date')
        if isinstance(art_date, datetime.datetime):
            date_str = art_date.astimezone(TZ_RO).strftime('%d %b %Y, %H:%M')
        else:
            date_str = str(art_date)

        card = f"""
        <div class="card {category_class}">
            <div class="card-header">
                <span class="source-tag">{html.escape(art['source'])}</span>
                <span class="date-tag">{date_str}</span>
                {score_badge}
                {new_badge}
                {infra_badge}
            </div>
            <h3 class="card-title"><a href="{html.escape(art['link'])}" target="_blank" rel="noopener">{title_formatted}</a></h3>
            <p class="card-desc">{desc_formatted}</p>
            {ioc_html}
        </div>
        """
        cards.append(card)
    return "\n".join(cards)

def build_web_dashboard(categorized):
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
    <title>Cyber Security Intelligence v4.6 Ultimate</title>
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
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-dark); color: var(--text-main); padding: 20px; line-height: 1.5; }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }}
        h1 {{ font-size: 1.8rem; font-weight: 700; color: #fff; }}
        .last-update {{ color: var(--text-muted); font-size: 0.9rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 25px; }}
        .stat-card {{ background: var(--card-bg); padding: 15px 20px; border-radius: 8px; border-left: 4px solid var(--border-color); }}
        .stat-card.targeted {{ border-left-color: var(--accent-targeted); }}
        .stat-card.critical {{ border-left-color: var(--accent-critical); }}
        .stat-card.general {{ border-left-color: var(--accent-general); }}
        .stat-value {{ font-size: 1.8rem; font-weight: bold; margin-top: 5px; }}
        .stat-label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; }}
        .controls {{ display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }}
        .search-box {{ flex: 1; min-width: 250px; padding: 10px 15px; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 6px; color: #fff; font-size: 0.95rem; }}
        .tabs {{ display: flex; gap: 8px; }}
        .tab-btn {{ background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 500; }}
        .tab-btn.active {{ background: var(--accent-general); border-color: var(--accent-general); color: #fff; }}
        .cards-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 20px; }}
        .card {{ background: var(--card-bg); border-radius: 8px; padding: 20px; border: 1px solid var(--border-color); display: flex; flex-direction: column; justify-content: space-between; }}
        .card.targeted-card {{ border-top: 3px solid var(--accent-targeted); }}
        .card.critical-card {{ border-top: 3px solid var(--accent-critical); }}
        .card.general-card {{ border-top: 3px solid var(--accent-general); }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem; margin-bottom: 12px; gap: 5px; flex-wrap: wrap; }}
        .source-tag {{ color: var(--text-muted); font-weight: 600; }}
        .date-tag {{ color: var(--text-muted); }}
        .badge {{ padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 0.7rem; }}
        .badge-new {{ background: #10b981; color: #fff; }}
        .badge-infra {{ background: #a855f7; color: #fff; }}
        .badge-score {{ background: #475569; color: #38bdf8; }}
        .cve-badge {{ background: #334155; color: #38bdf8; padding: 2px 6px; border-radius: 4px; text-decoration: none; font-size: 0.85rem; font-family: monospace; }}
        .ioc-container {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }}
        .ioc-pill {{ background: #0f172a; color: #f43f5e; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; font-family: monospace; border: 1px solid #334155; }}
        .card-title {{ font-size: 1.1rem; margin-bottom: 10px; line-height: 1.3; }}
        .card-title a {{ color: #fff; text-decoration: none; }}
        .card-title a:hover {{ color: var(--accent-general); }}
        .card-desc {{ color: var(--text-muted); font-size: 0.9rem; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }}
        .no-data {{ color: var(--text-muted); grid-column: 1 / -1; padding: 40px; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Cyber Security Intelligence (31 Surse)</h1>
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
            <input type="text" id="searchInput" class="search-box" placeholder="Căutare după termen, CVE sau IP..." onkeyup="filterCards()">
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
                card.style.display = (matchesSearch && matchesCategory) ? 'flex' : 'none';
            }});
        }}
    </script>
</body>
</html>"""

    filename = "index.html"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filename
    except OSError:
        fallback = os.path.join(tempfile.gettempdir(), filename)
        with open(fallback, "w", encoding="utf-8") as f:
            f.write(html_content)
        return fallback

# ==========================================
# 2) GENERATOR EMAIL MOBILE-BULLETPROOF (INDEPENDENT de index.html)
# ==========================================
#
# De ce e separat de build_web_dashboard():
# În v4.2, send_email() citea și trimitea DIRECT fișierul index.html ca și corp de mail.
# Acel HTML se bazează pe CSS Grid, Flexbox și variabile CSS (var(--...)) — toate nesuportate
# de motoarele de randare ale clienților de email (Gmail web/app, Outlook, etc). Rezultatul:
# proprietățile cad silențios, iar layout-ul se prăbușește la comportamentul default
# block/inline, exact tiparul de randare stricat observat pe mobil.
#
# Regulile de construcție de mai jos, aplicate consecvent:
#   1. Fără CSS Grid, Flexbox sau var() — doar tabele HTML + stiluri inline cu valori fixe.
#   2. Fără colspan combinat cu alte <td> pe același rând (Gmail Android calculează lățimile
#      coloanelor din primul rând și le fixează pentru tot tabelul).
#   3. Tabel exterior width="100%" + max-width:600px (nu width fix), pentru ecrane ~360-380px.
#   4. bgcolor="#..." redundant lângă background-color (unii clienți strip-uiesc CSS de fundal).
#   5. word-break/overflow-wrap pe titluri, descrieri, CVE-uri lungi fără spații.
#   6. <meta name="color-scheme"> ca să nu las auto-dark-mode să inverseze designul.
#   7. Linkuri cu culoare + text-decoration explicite direct pe <a>.
#   8. role="presentation" + reset MSO pentru Outlook desktop (motor Word).
#   9. Preheader ascuns pentru preview-ul din inbox.
#  10. Badge-uri cu white-space:nowrap, fiecare pe rândul lor propriu.
#

def build_mobile_email_html(categorized):
    now_ro_str = datetime.datetime.now(TZ_RO).strftime('%d %b %Y, %H:%M')
    total_targeted = len(categorized['targeted'])
    total_critical = len(categorized['critical'])
    total_general = len(categorized['general'])
    total_all = total_targeted + total_critical + total_general

    top_alert_title = None
    for key in ('targeted', 'critical', 'general'):
        if categorized[key]:
            top_alert_title = categorized[key][0]['title']
            break
    preheader_text = (
        f"{total_all} alerte noi \u2022 {total_targeted} vizate \u2022 {total_critical} critice"
        + (f" \u2014 {top_alert_title}" if top_alert_title else "")
    )

    def render_badges_row(art):
        badges = []
        badges.append(
            f'<span style="display:inline-block; white-space:nowrap; background-color:#334155; '
            f'color:#38bdf8; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:bold; '
            f'margin:0 6px 4px 0;">SCORE: {art.get("risk_score", 0)}</span>'
        )
        if art['is_new']:
            badges.append(
                '<span style="display:inline-block; white-space:nowrap; background-color:#10b981; '
                'color:#ffffff; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:bold; '
                'margin:0 6px 4px 0;">NOU</span>'
            )
        if art.get('is_targeted_infra'):
            badges.append(
                '<span style="display:inline-block; white-space:nowrap; background-color:#a855f7; '
                'color:#ffffff; padding:3px 8px; border-radius:4px; font-size:11px; font-weight:bold; '
                'margin:0 6px 4px 0;">INFRA</span>'
            )
        return "".join(badges)

    def render_card(art, accent_color):
        art_date = art.get('date')
        if isinstance(art_date, datetime.datetime):
            date_str = art_date.astimezone(TZ_RO).strftime('%d %b, %H:%M')
        else:
            date_str = str(art_date)

        badges_html = render_badges_row(art)

        iocs_row = ""
        if art['iocs']['cves'] or art['iocs']['ips']:
            cve_txt = "".join([
                f'<span style="display:inline-block; white-space:nowrap; background-color:#0f172a; '
                f'color:#f43f5e; padding:2px 6px; border-radius:3px; font-family:monospace; '
                f'font-size:11px; border:1px solid #334155; margin:0 4px 4px 0;">{html.escape(c)}</span>'
                for c in art['iocs']['cves'][:3]
            ])
            iocs_row = f"""
            <tr>
                <td style="padding-top:6px; word-break:break-word; overflow-wrap:break-word;">
                    {cve_txt}
                </td>
            </tr>
            """

        link_safe = html.escape(art['link'])
        title_safe = html.escape(art['title'])
        desc_safe = html.escape(art['description'])
        source_safe = html.escape(art['source'])

        return f"""
        <tr>
            <td bgcolor="#1e293b" style="background-color:#1e293b; border:1px solid #334155; border-left:4px solid {accent_color}; border-radius:6px; padding:14px;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="table-layout:fixed; width:100%;">
                    <tr>
                        <td style="font-size:12px; color:#94a3b8; padding-bottom:8px; word-break:break-word;">
                            <strong style="color:#cbd5e1;">{source_safe}</strong> &bull; {date_str}
                        </td>
                    </tr>
                    <tr>
                        <td style="padding-bottom:8px; line-height:1.6;">
                            {badges_html}
                        </td>
                    </tr>
                    <tr>
                        <td style="font-size:16px; font-weight:bold; padding-bottom:8px; line-height:1.4; word-break:break-word; overflow-wrap:break-word;">
                            <a href="{link_safe}" target="_blank" style="color:#ffffff; text-decoration:none; word-break:break-word;">{title_safe}</a>
                        </td>
                    </tr>
                    <tr>
                        <td style="font-size:14px; color:#94a3b8; line-height:1.5; word-break:break-word; overflow-wrap:break-word;">
                            {desc_safe}
                        </td>
                    </tr>
                    {iocs_row}
                </table>
            </td>
        </tr>
        <tr><td height="10" style="line-height:10px; font-size:10px;">&nbsp;</td></tr>
        """

    def render_section_rows(articles, accent_color, section_title):
        if not articles:
            return f"""
            <tr>
                <td bgcolor="#1e293b" style="padding:12px 16px; background-color:#1e293b; color:#94a3b8; font-size:14px; border-radius:6px;">
                    <strong>{html.escape(section_title)} (0):</strong> Nicio alertă în intervalul analizat.
                </td>
            </tr>
            <tr><td height="12" style="line-height:12px; font-size:12px;">&nbsp;</td></tr>
            """

        rows = [f"""
        <tr>
            <td style="padding-top:10px; padding-bottom:6px;">
                <span style="font-size:15px; font-weight:bold; color:{accent_color}; text-transform:uppercase;">
                    {html.escape(section_title)} ({len(articles)})
                </span>
            </td>
        </tr>
        """]

        for art in articles:
            rows.append(render_card(art, accent_color))

        return "\n".join(rows)

    email_html = f"""<!DOCTYPE html>
<html lang="ro" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="color-scheme" content="dark light">
    <meta name="supported-color-schemes" content="dark light">
    <title>Cyber Security Intelligence</title>
    <!--[if mso]>
    <noscript>
        <xml>
            <o:OfficeDocumentSettings>
                <o:PixelsPerInch>96</o:PixelsPerInch>
            </o:OfficeDocumentSettings>
        </xml>
    </noscript>
    <style>
        table {{ border-collapse: collapse; }}
        td, a, span {{ font-family: Arial, Helvetica, sans-serif !important; }}
    </style>
    <![endif]-->
    <style>
        body, table, td, a {{ -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }}
        table, td {{ mso-table-lspace: 0pt; mso-table-rspace: 0pt; }}
        img {{ -ms-interpolation-mode: bicubic; border: 0; }}
        body {{ margin: 0; padding: 0; width: 100% !important; height: 100% !important; }}
        a {{ text-decoration: none; }}
        @media only screen and (max-width: 600px) {{
            .email-container {{ width: 100% !important; max-width: 100% !important; }}
            .fluid-padding {{ padding-left: 14px !important; padding-right: 14px !important; }}
        }}
    </style>
</head>
<body style="margin:0; padding:0; background-color:#0f172a; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color:#f8fafc;">
    <div style="display:none; max-height:0; overflow:hidden; mso-hide:all; font-size:1px; line-height:1px; color:#0f172a; opacity:0;">
        {html.escape(preheader_text)}
    </div>
    <div style="display:none; max-height:0; overflow:hidden; mso-hide:all;">
        &nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;
    </div>

    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#0f172a" style="background-color:#0f172a;">
        <tr>
            <td align="center" style="padding:20px 0;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="email-container" style="max-width:600px; width:100%;">

                    <tr>
                        <td bgcolor="#1e293b" class="fluid-padding" style="padding:20px; background-color:#1e293b; border-radius:8px 8px 0 0; border-bottom:1px solid #334155;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                                <tr>
                                    <td style="font-size:20px; font-weight:bold; color:#ffffff;">
                                        Cyber Security Intelligence
                                    </td>
                                </tr>
                                <tr>
                                    <td style="font-size:13px; color:#94a3b8; padding-top:4px;">
                                        Sincronizat la: {now_ro_str} &bull; 31 Surse Active
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <tr>
                        <td bgcolor="#1e293b" class="fluid-padding" style="background-color:#1e293b; padding:15px 20px; border-bottom:1px solid #334155;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                                <tr>
                                    <td width="25%" align="center" style="font-size:12px; color:#94a3b8; text-transform:uppercase; padding:4px;">
                                        Total<br><span style="font-size:18px; font-weight:bold; color:#ffffff;">{total_all}</span>
                                    </td>
                                    <td width="25%" align="center" style="font-size:12px; color:#94a3b8; text-transform:uppercase; padding:4px;">
                                        Vizate<br><span style="font-size:18px; font-weight:bold; color:#f59e0b;">{total_targeted}</span>
                                    </td>
                                    <td width="25%" align="center" style="font-size:12px; color:#94a3b8; text-transform:uppercase; padding:4px;">
                                        Critice<br><span style="font-size:18px; font-weight:bold; color:#ef4444;">{total_critical}</span>
                                    </td>
                                    <td width="25%" align="center" style="font-size:12px; color:#94a3b8; text-transform:uppercase; padding:4px;">
                                        Generale<br><span style="font-size:18px; font-weight:bold; color:#3b82f6;">{total_general}</span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <tr>
                        <td bgcolor="#0f172a" class="fluid-padding" style="padding:20px; background-color:#0f172a;">
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                                {render_section_rows(categorized['targeted'], '#f59e0b', 'Infrastructură Vizată')}
                                {render_section_rows(categorized['critical'], '#ef4444', 'Alerte Critice / Threat Intel')}
                                {render_section_rows(categorized['general'], '#3b82f6', 'Alerte Generale Vulnerabilități')}
                            </table>
                        </td>
                    </tr>

                    <tr>
                        <td bgcolor="#0f172a" align="center" style="padding:20px; text-align:center; font-size:12px; color:#64748b; background-color:#0f172a; border-top:1px solid #1e293b;">
                            Generat automat de motorul Cyber Security Intelligence v4.6 &bull; Toate drepturile rezervate.
                        </td>
                    </tr>

                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""
    return email_html

def html_to_plain_text(categorized):
    lines = ["RAPORT ZILNIC CYBER SECURITY INTELLIGENCE (31 SURSE)", "=" * 55, ""]
    for label, key in [("INFRASTRUCTURĂ VIZATĂ", "targeted"),
                        ("ALERTE CRITICE", "critical"),
                        ("ALERTE GENERALE", "general")]:
        lines.append(f"-- {label} ({len(categorized[key])}) --")
        if not categorized[key]:
            lines.append("  (nicio alertă în ultimele 36h)")
        for art in categorized[key]:
            art_date = art.get('date')
            if isinstance(art_date, datetime.datetime):
                date_ro = art_date.astimezone(TZ_RO).strftime('%d %b %Y, %H:%M')
            else:
                date_ro = str(art_date)
            lines.append(f"  [{art['source']}] (Score: {art['risk_score']}) {art['title']} ({date_ro})")
            lines.append(f"    {art['link']}")
        lines.append("")
    return "\n".join(lines)

def send_email(categorized):
    """
    NOTĂ: nu mai primește/citește html_file_path (index.html). Corpul de email e generat
    independent de build_mobile_email_html(), tocmai ca să nu se mai trimită dashboard-ul
    web (CSS Grid/Flexbox/var()) direct ca și corp de mail.
    """
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_to_raw = os.getenv("EMAIL_TO")

    if not all([smtp_server, smtp_user, smtp_password, email_to_raw]):
        print("[!] Variabilele de mediu SMTP nu sunt complet configurate. Email-ul nu a fost trimis.")
        return

    email_to_list = [addr.strip() for addr in email_to_raw.split(",") if addr.strip()]
    if not email_to_list:
        return

    now_ro_str = datetime.datetime.now(TZ_RO).strftime('%d %b %Y')
    msg = MIMEMultipart("alternative")
    msg['Subject'] = Header(f"Raport Zilnic Cyber Security Intelligence - {now_ro_str}", "utf-8")
    msg['From'] = smtp_user
    msg['To'] = ", ".join(email_to_list)

    email_html_body = build_mobile_email_html(categorized)
    plain_body = html_to_plain_text(categorized)

    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(email_html_body, "html", "utf-8"))

    try:
        context = ssl.create_default_context()
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=15, context=context) as server:
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, email_to_list, msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
                server.starttls(context=context)
                server.login(smtp_user, smtp_password)
                server.sendmail(smtp_user, email_to_list, msg.as_string())
        print("[+] Notificarea pe email optimizată pentru mobil a fost trimisă cu succes.")
    except Exception as e:
        print(f"[!] Eroare trimitere email: {e}")

if __name__ == "__main__":
    print("[*] Rulare motor Cyber Security Intelligence v4.6...")
    categorized_data = fetch_and_filter()
    saved_path = build_web_dashboard(categorized_data)
    print(f"[+] Dashboard web generat cu succes la: {saved_path}")

    now_ro = datetime.datetime.now(TZ_RO)
    force_email = os.getenv("FORCE_EMAIL", "false").lower() == "true"
    if now_ro.hour == 8 or force_email or os.getenv("GITHUB_EVENT_NAME") == "workflow_dispatch":
        print("[*] Se inițiază trimiterea email-ului de notificare (corp dedicat, independent de index.html)...")
        send_email(categorized_data)
