#!/usr/bin/env python3
"""
Cyber Security Monitoring & Intelligence Engine (v4.8 - Mobile-Bulletproof Enterprise Edition)
-----------------------------------------------------------------------------------------
- Extindere la 61+ surse RSS/Atom de securitate cu priorități ponderate.
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
# CONFIGURARE CELE 61+ SURSE ȘI PRIORITĂȚI
# ==========================================

RSS_SOURCES = [
    # Surse Naționale & Oficiale / Guvernamentale
    {"name": "NCSC UK - News & Threats", "url": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml", "priority": 90},

    # Threat Intelligence & Știri Securitate Enterprise
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "priority": 75},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "priority": 75},
    {"name": "Krebs on Security", "url": "http://feeds.feedburner.com/krebsonsecurity", "priority": 80},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "priority": 70},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "priority": 65},
    {"name": "Ars Technica - Security", "url": "https://arstechnica.com/security/feed/", "priority": 70},
    {"name": "SANS ISC StormCast", "url": "https://isc.sans.edu/rssfeed.xml", "priority": 85},
    {"name": "Kaspersky Securelist", "url": "https://securelist.com/feed/", "priority": 80},
    {"name": "Malwarebytes Labs", "url": "https://www.malwarebytes.com/blog/feed/index.xml", "priority": 75},
    {"name": "Schneier on Security", "url": "https://www.schneier.com/feed/atom/", "priority": 75},
    {"name": "The Register - Security", "url": "https://www.theregister.com/security/headlines.atom", "priority": 70},
    {"name": "CSO Online", "url": "https://www.csoonline.com/feed/", "priority": 65},
    {"name": "Help Net Security", "url": "https://www.helpnetsecurity.com/feed/", "priority": 70},
    {"name": "HackRead", "url": "https://www.hackread.com/feed/", "priority": 65},

    # Windows și Ecosistemul Microsoft
    {"name": "Microsoft Security Response (MSRC)", "url": "https://api.msrc.microsoft.com/update-guide/rss", "priority": 95},
    {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/", "priority": 85},

    # Threat Intel Vendori & Infra
    {"name": "Cisco Talos Intelligence", "url": "https://blog.talosintelligence.com/rss/", "priority": 85},
    {"name": "Unit 42 (Palo Alto Networks)", "url": "https://unit42.paloaltonetworks.com/feed/", "priority": 85},
    {"name": "CrowdStrike Blog", "url": "https://www.crowdstrike.com/blog/feed/", "priority": 85},
    {"name": "Check Point Research", "url": "https://research.checkpoint.com/feed/", "priority": 80},
    {"name": "ESET WeLiveSecurity", "url": "https://www.welivesecurity.com/feed/", "priority": 75},
    {"name": "Rapid7 Blog", "url": "https://blog.rapid7.com/rss/", "priority": 80},
    {"name": "Red Canary Blog", "url": "https://redcanary.com/feed/", "priority": 80},
    {"name": "Censys Research", "url": "https://censys.com/feed/", "priority": 75},

    # Android și Securitate Mobilă
    {"name": "Google Online Security Blog", "url": "https://security.googleblog.com/feeds/posts/default", "priority": 85},
    {"name": "Android Police - News", "url": "https://www.androidpolice.com/feed/", "priority": 60},
    {"name": "Android Authority", "url": "https://www.androidauthority.com/feed/", "priority": 60},
    {"name": "9to5Google - Security", "url": "https://9to5google.com/category/security/feed/", "priority": 65},

    # Hardware Hacks și Securitate Low-Level / Embedded
    {"name": "Hackaday", "url": "https://hackaday.com/feed/", "priority": 65},
    {"name": "Tom's Hardware", "url": "https://www.tomshardware.com/feeds/all", "priority": 60},
    {"name": "IEEE Spectrum", "url": "https://spectrum.ieee.org/rss/fulltext", "priority": 65},
    {"name": "Phoronix", "url": "https://www.phoronix.com/rss.php", "priority": 60},

    # Platforme Web, Cloud & Tehnologii Direct Vizate
    {"name": "Joomla Community News", "url": "https://community.joomla.org/blogs.feed?type=rss", "priority": 90},
    {"name": "Joomla Security Announcements", "url": "https://developer.joomla.org/security-centre.feed?type=rss", "priority": 95},
    {"name": "PHP.net News", "url": "https://www.php.net/news.rss", "priority": 90},
    {"name": "Cloudflare Blog - Security", "url": "https://blog.cloudflare.com/tag/security/rss/", "priority": 85},
    {"name": "GitHub Security Advisories", "url": "https://github.blog/category/security/feed/", "priority": 85},
    {"name": "Project Zero (Google)", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "priority": 95},
    {"name": "PortSwigger Web Security", "url": "https://portswigger.net/research/rss", "priority": 90},
    {"name": "Wordfence Security Blog", "url": "https://www.wordfence.com/feed/", "priority": 85},

    # --- Adăugate/verificate de pe runner-ul GitHub (probe 8 oct. 2026) ---
    {"name": "DNSC - Știri și alerte", "url": "https://www.dnsc.ro/feed", "priority": 95},
    {"name": "CISA - Known Exploited Vulnerabilities", "type": "cisa_kev", "priority": 100,
     "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "urls": ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
              "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"]},
    {"name": "NVD NIST - Critical CVEs", "type": "nvd_api", "push": False, "priority": 90,
     "url": "https://services.nvd.nist.gov/rest/json/cves/2.0"},
    {"name": "CERT-EU - Security Advisories", "url": "https://cert.europa.eu/publications/security-advisories-rss", "priority": 90},
    {"name": "CERT-EU - Threat Intelligence", "url": "https://cert.europa.eu/publications/threat-intelligence-rss", "priority": 85},
    {"name": "CERT/CC - Vulnerability Notes", "url": "https://kb.cert.org/vuls/atomfeed/", "priority": 90},
    {"name": "AWS Security Bulletins", "url": "https://aws.amazon.com/security/security-bulletins/feed/", "priority": 90},
    {"name": "AWS Security Blog", "url": "https://aws.amazon.com/blogs/security/feed/", "priority": 80},
    {"name": "Google Cloud Threat Intelligence", "url": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", "priority": 85},
    {"name": "SentinelOne Labs", "url": "https://www.sentinelone.com/labs/feed/", "priority": 80},
    {"name": "Zero Day Initiative", "url": "https://www.zerodayinitiative.com/rss/published/", "priority": 85},
    {"name": "Elastic Security Labs", "url": "https://www.elastic.co/security-labs/rss/feed.xml", "priority": 85},
    {"name": "watchTowr Labs", "url": "https://labs.watchtowr.com/rss/", "priority": 85},
    {"name": "Huntress Blog", "url": "https://www.huntress.com/blog/rss.xml", "priority": 80},
    {"name": "Citizen Lab", "url": "https://citizenlab.ca/feed/", "priority": 75},
    {"name": "The Record (Recorded Future News)", "url": "https://therecord.media/feed", "priority": 75},
    {"name": "Health-ISAC", "url": "https://health-isac.org/feed/", "priority": 85},
    {"name": "Chrome Releases", "url": "https://chromereleases.googleblog.com/feeds/posts/default", "priority": 75},
    {"name": "PHP.net - Releases", "url": "https://www.php.net/releases/feed.php", "priority": 90},
]

SOURCE_PRIORITY_MAP = {src['name']: src['priority'] for src in RSS_SOURCES}

KEYWORDS_TARGETED = [
    "joomla", "php", "cpanel", "apache", ".htaccess", "mysql", "mariadb",
    "exim", "roundcube", "bind9", "isc bind", "named.conf", "mod_security", "whm"
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
# Surse rare dar importante: fereastra de 36h le golește aproape mereu (ex. Joomla, PHP.net).
LONG_WINDOW_HOURS = 168
LONG_WINDOW_SOURCES = {
    "Joomla Security Announcements", "Joomla Community News", "PHP.net News", "PHP.net - Releases",
    "Wordfence Security Blog", "Project Zero (Google)", "Google Online Security Blog",
    "PortSwigger Web Security", "NCSC UK - News & Threats", "GitHub Security Advisories",
    "Kaspersky Securelist", "DNSC - Știri și alerte", "CISA - Known Exploited Vulnerabilities",
    "CERT-EU - Security Advisories", "CERT/CC - Vulnerability Notes", "AWS Security Bulletins",
    "Zero Day Initiative", "Health-ISAC",
}
# Surse de consum/hardware: păstrăm doar articolele cu semnal real de securitate.
NOISY_SOURCES = {
    "Android Authority", "Android Police - News", "Tom's Hardware", "Phoronix",
    "Hackaday", "IEEE Spectrum", "9to5Google - Security",
}
KEYWORDS_STRICT_SECURITY = [
    "cve-", "vulnerability", "vulnerabilities", "exploit", "exploited", "malware", "ransomware",
    "phishing", "zero-day", "0-day", "security update", "security patch", "backdoor", "botnet",
    "side-channel", "spectre", "meltdown", "microcode",
]

def lookback_for(source_name):
    return LONG_WINDOW_HOURS if source_name in LONG_WINDOW_SOURCES else HOURS_LOOKBACK

# Notificări push (ntfy): active doar dacă NTFY_TOPIC este setat.
NTFY_MIN_SCORE = int(os.getenv("NTFY_MIN_SCORE", "80"))
NTFY_MAX_PER_RUN = 5
SOURCES_LABEL = f"{len(RSS_SOURCES)} surse configurate"
MAX_THREADS = min(32, max(8, len(RSS_SOURCES)))
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
        "%a, %d %b %Y %H:%M:%S",
        "%b %d, %Y %H:%M:%S%z",      # CrowdStrike: "Oct 08, 2026 00:00:00-0500"
        "%d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S",         # fără zi a săptămânii/fus: se presupune UTC
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
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
            if 400 <= e.code < 500 and e.code not in (408, 429):
                break  # 403/404/410 sunt permanente: retry doar consumă timp
            if attempt < HTTP_RETRY_ATTEMPTS - 1:
                time.sleep(HTTP_RETRY_BACKOFF_BASE * (attempt + 1))
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_error = e
            if attempt < HTTP_RETRY_ATTEMPTS - 1:
                time.sleep(HTTP_RETRY_BACKOFF_BASE * (attempt + 1))
    raise last_error

FEED_HEALTH = {}

def _serialize_articles(articles):
    out = []
    for art in articles:
        c = art.copy()
        if isinstance(c.get('date'), datetime.datetime):
            c['date'] = c['date'].isoformat()
        c.pop('date_obj', None)
        out.append(c)
    return out

def _make_article(source, title, link, description, pub_dt):
    clean_desc = html.unescape(description or "")[:300]
    clean_desc = clean_desc + "..." if description else ""
    return {
        'source': source['name'],
        'title': title,
        'link': normalize_url(link),
        'description': clean_desc,
        'date': pub_dt.isoformat(),
        'date_obj': pub_dt,
        'date_unknown': False,
        'iocs': extract_iocs(f"{title} {clean_desc}"),
        'no_push': source.get('push') is False,
    }

def parse_cisa_kev(data, source, now_utc):
    threshold = now_utc - datetime.timedelta(hours=lookback_for(source['name']))
    articles = []
    for v in data.get('vulnerabilities', []):
        try:
            added = datetime.datetime.strptime(v['dateAdded'], '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
        except (KeyError, ValueError):
            continue
        if added < threshold:
            continue
        cve = v.get('cveID', '')
        ransom = " Folosit în campanii ransomware." if v.get('knownRansomwareCampaignUse') == 'Known' else ""
        title = f"CISA KEV: {cve} — {v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')}".strip()
        desc = (f"Exploited in the wild (CISA Known Exploited Vulnerabilities, adăugat {v['dateAdded']}).{ransom} "
                f"{v.get('shortDescription', '')}")
        articles.append(_make_article(source, title, f"https://nvd.nist.gov/vuln/detail/{cve}", desc, added))
    return articles

def parse_nvd(data, source, now_utc):
    articles = []
    for item in data.get('vulnerabilities', []):
        cve = item.get('cve', {})
        cid = cve.get('id')
        if not cid:
            continue
        try:
            pub = datetime.datetime.fromisoformat(cve['published'])
        except (KeyError, ValueError):
            continue
        if pub.tzinfo is None:
            pub = pub.replace(tzinfo=datetime.timezone.utc)
        desc = next((d.get('value', '') for d in cve.get('descriptions', []) if d.get('lang') == 'en'), "")
        score = None
        for key in ('cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30'):
            metrics = cve.get('metrics', {}).get(key)
            if metrics:
                score = metrics[0].get('cvssData', {}).get('baseScore')
                break
        score_txt = f" (CVSS {score})" if score is not None else ""
        title = f"NVD critical vulnerability: {cid}{score_txt} {desc[:110]}".strip()
        articles.append(_make_article(source, title, f"https://nvd.nist.gov/vuln/detail/{cid}", desc, pub))
    return articles

def _nvd_request_url(source, now_utc):
    start = now_utc - datetime.timedelta(hours=HOURS_LOOKBACK)
    fmt = lambda d: urllib.parse.quote(d.strftime('%Y-%m-%dT%H:%M:%S.000') + '+00:00')
    return (f"{source['url']}?cvssV3Severity=CRITICAL&resultsPerPage=100"
            f"&pubStartDate={fmt(start)}&pubEndDate={fmt(now_utc)}")

def fetch_json_source(source, http_cache):
    """Surse JSON (CISA KEV, NVD API). La eroare se folosesc articolele din cache (stale)."""
    cache_key = f"json::{source['name']}"
    cache_entry = http_cache.get(cache_key, {})
    headers = {'User-Agent': 'CyberSecurityMonitor/4.8', 'Accept': 'application/json'}
    if source['type'] == 'nvd_api' and os.getenv("NVD_API_KEY"):
        headers['apiKey'] = os.getenv("NVD_API_KEY")
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    try:
        urls = source.get('urls') or [source['url']]
        last_err = None
        data = None
        for base in urls:
            try:
                url = _nvd_request_url(source, now_utc) if source['type'] == 'nvd_api' else base
                content, _, _, _ = _fetch_url_with_retry(url, headers, REQUEST_TIMEOUT * 2)
                data = json.loads(content)
                break
            except Exception as e:
                last_err = e
        if data is None:
            raise last_err
        parser = parse_cisa_kev if source['type'] == 'cisa_kev' else parse_nvd
        articles = parser(data, source, now_utc)
        http_cache[cache_key] = {'etag': None, 'last_modified': None, 'cached_articles': _serialize_articles(articles)}
        FEED_HEALTH[source['name']] = {'ok': True, 'status': f"JSON {len(articles)}"}
        return articles
    except Exception as e:
        print(f"[!] Eroare la sursa JSON '{source['name']}': {type(e).__name__}: {str(e)[:100]}")
        stale = _restore_cached_articles(cache_entry)
        FEED_HEALTH[source['name']] = {'ok': False, 'status': f"{type(e).__name__}: {str(e)[:80]}", 'stale': len(stale)}
        return stale

def _restore_cached_articles(cache_entry):
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

def fetch_single_feed(source, http_cache):
    if source.get('type') in ('cisa_kev', 'nvd_api'):
        return fetch_json_source(source, http_cache)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CyberSecurityMonitor/4.8'
    }

    cache_entry = http_cache.get(source['url'], {})
    if cache_entry.get('etag'):
        headers['If-None-Match'] = cache_entry['etag']
    if cache_entry.get('last_modified'):
        headers['If-Modified-Since'] = cache_entry['last_modified']

    try:
        content, new_etag, new_last_modified, status_code = _fetch_url_with_retry(source['url'], headers, REQUEST_TIMEOUT)
        if status_code == 304:
            FEED_HEALTH[source['name']] = {'ok': True, 'status': '304'}
            return _restore_cached_articles(cache_entry)
    except Exception as e:
        print(f"[!] Eroare la sursa '{source['name']}': {type(e).__name__}: {e}")
        stale = _restore_cached_articles(cache_entry)  # nu pierdem articolele deja cunoscute la o eroare tranzitorie
        FEED_HEALTH[source['name']] = {'ok': False, 'status': f"{type(e).__name__}: {str(e)[:80]}", 'stale': len(stale)}
        return stale

    articles = []
    try:
        root = ET.fromstring(content)
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        threshold_time = now_utc - datetime.timedelta(hours=lookback_for(source['name']))

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
        FEED_HEALTH[source['name']] = {'ok': True, 'status': '200'}
    except Exception as e:
        print(f"[!] Eroare parsare XML pentru '{source['name']}': {e}")
        stale = _restore_cached_articles(cache_entry)
        FEED_HEALTH[source['name']] = {'ok': False, 'status': f"Parse: {str(e)[:80]}", 'stale': len(stale)}
        return stale

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

LAST_CACHE = {}

def _age_hours(iso, now_utc):
    try:
        return (now_utc - datetime.datetime.fromisoformat(iso)).total_seconds() / 3600
    except (ValueError, TypeError):
        return 0

def fetch_and_filter():
    cache = load_cache()

    global LAST_CACHE, SOURCES_LABEL
    LAST_CACHE = cache
    force_refresh = os.getenv("FORCE_REFRESH", "").lower() == "true"

    if force_refresh:
        print("[*] FORCE_REFRESH activ: se resetează cache-ul HTTP pentru date proaspete.")
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
                    if (now_utc - fs).total_seconds() / 3600 <= lookback_for(art['source']):
                        bounded_deduped.append(art)
                except ValueError:
                    bounded_deduped.append(art)
        else:
            if isinstance(art.get('date'), datetime.datetime) and (now_utc - art['date']).total_seconds() / 3600 <= lookback_for(art['source']):
                bounded_deduped.append(art)

    # Prune first_seen (crește nelimitat altfel) și înregistrează sănătatea surselor
    first_seen_cache = {k: v for k, v in first_seen_cache.items()
                        if _age_hours(v, now_utc) <= LONG_WINDOW_HOURS}
    ok_count = sum(1 for src in RSS_SOURCES if FEED_HEALTH.get(src['name'], {}).get('ok'))
    failed = {n: h['status'] for n, h in FEED_HEALTH.items() if not h.get('ok')}
    SOURCES_LABEL = f"{ok_count}/{len(RSS_SOURCES)} surse active"
    print(f"[*] Surse active: {ok_count}/{len(RSS_SOURCES)}; eșuate: {len(failed)}")
    for n, st in sorted(failed.items()):
        print(f"    - {n}: {st}")
    # Elimină intrările HTTP ale surselor scoase din configurare (cache-ul nu mai crește cu surse moarte)
    valid_keys = {src['url'] for src in RSS_SOURCES} | {f"json::{src['name']}" for src in RSS_SOURCES if src.get('type')}
    http_cache = {k: v for k, v in http_cache.items() if k in valid_keys}
    cache['first_seen'] = first_seen_cache
    cache['http_cache'] = http_cache
    cache['feed_health'] = {'updated': now_utc.isoformat(), 'ok': ok_count,
                            'total': len(RSS_SOURCES), 'failed': failed}
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

        if art['source'] in NOISY_SOURCES and not (
                is_targeted_infra or has_critical or art['iocs']['cves']
                or contains_keyword(text_to_scan, KEYWORDS_STRICT_SECURITY)):
            continue

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
# 1) GENERATOR DASHBOARD WEB (GitHub Pages)
# ==========================================

RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

def format_cve(text):
    if not text:
        return ""
    escaped_text = html.escape(text)
    return RE_CVE.sub(
        lambda m: f'<a href="https://nvd.nist.gov/vuln/detail/{m.group(0)}" target="_blank" class="cve-badge">{m.group(0)}</a>',
        escaped_text
    )

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
    <title>Cyber Security Intelligence v4.8 Enterprise Hub</title>
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
        html {{ -webkit-text-size-adjust: 100%; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-dark); color: var(--text-main); padding: 20px; padding-left: max(20px, env(safe-area-inset-left)); padding-right: max(20px, env(safe-area-inset-right)); line-height: 1.5; overflow-wrap: anywhere; }}
        a:focus-visible, button:focus-visible, input:focus-visible {{ outline: 2px solid #93c5fd; outline-offset: 2px; }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--border-color); margin-bottom: 25px; flex-wrap: wrap; gap: 15px; }}
        h1 {{ font-size: clamp(1.25rem, 4.5vw, 1.8rem); font-weight: 700; color: #fff; }}
        .last-update {{ color: var(--text-muted); font-size: 0.9rem; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 200px), 1fr)); gap: 12px; margin-bottom: 20px; }}
        .stat-card {{ background: var(--card-bg); padding: 15px 20px; border-radius: 8px; border-left: 4px solid var(--border-color); }}
        .stat-card.targeted {{ border-left-color: var(--accent-targeted); }}
        .stat-card.critical {{ border-left-color: var(--accent-critical); }}
        .stat-card.general {{ border-left-color: var(--accent-general); }}
        .stat-value {{ font-size: 1.8rem; font-weight: bold; margin-top: 5px; }}
        .stat-label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; }}
        .controls {{ display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }}
        .search-box {{ flex: 1 1 250px; min-width: 0; min-height: 44px; padding: 10px 15px; background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 6px; color: #fff; font-size: 0.95rem; }}
        .tabs {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .tab-btn {{ background: var(--card-bg); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 16px; min-height: 44px; border-radius: 6px; cursor: pointer; font-weight: 500; font-size: 0.95rem; }}
        .tab-btn.active {{ background: #1d4ed8; border-color: #1d4ed8; color: #fff; }}
        .cards-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr)); gap: 16px; }}
        .card {{ min-width: 0; background: var(--card-bg); border-radius: 8px; padding: 16px; border: 1px solid var(--border-color); display: flex; flex-direction: column; justify-content: space-between; }}
        .card.targeted-card {{ border-top: 3px solid var(--accent-targeted); }}
        .card.critical-card {{ border-top: 3px solid var(--accent-critical); }}
        .card.general-card {{ border-top: 3px solid var(--accent-general); }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; font-size: 0.8rem; margin-bottom: 12px; gap: 5px; flex-wrap: wrap; }}
        .source-tag {{ color: var(--text-muted); font-weight: 600; }}
        .date-tag {{ color: var(--text-muted); }}
        .badge {{ padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
        .badge-new {{ background: #047857; color: #fff; }}
        .badge-infra {{ background: #7e22ce; color: #fff; }}
        .badge-score {{ background: #0f172a; color: #7dd3fc; border: 1px solid #475569; }}
        .cve-badge {{ background: #334155; color: #38bdf8; padding: 2px 6px; border-radius: 4px; text-decoration: none; font-size: 0.85rem; font-family: monospace; }}
        .ioc-container {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; }}
        .ioc-pill {{ background: #0f172a; color: #f43f5e; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; font-family: monospace; border: 1px solid #334155; }}
        .card-title {{ font-size: 1.05rem; margin-bottom: 10px; line-height: 1.35; overflow-wrap: anywhere; }}
        .card-title a {{ color: #fff; text-decoration: none; }}
        .card-title a:hover {{ color: var(--accent-general); }}
        .card-desc {{ color: var(--text-muted); font-size: 0.9rem; overflow-wrap: anywhere; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }}
        @media (max-width: 480px) {{ body {{ padding: 12px; padding-left: max(12px, env(safe-area-inset-left)); padding-right: max(12px, env(safe-area-inset-right)); }} header {{ margin-bottom: 16px; }} .tabs {{ width: 100%; }} .tab-btn {{ flex: 1 1 auto; padding: 8px 10px; }} .stat-card {{ padding: 12px 16px; }} .stat-value {{ font-size: 1.5rem; }} }}
        @media (prefers-reduced-motion: reduce) {{ * {{ scroll-behavior: auto !important; }} }}
        .no-data {{ color: var(--text-muted); grid-column: 1 / -1; padding: 40px; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Cyber Security Intelligence Hub ({SOURCES_LABEL})</h1>
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
            <input type="search" id="searchInput" class="search-box" aria-label="Căutare după termen, CVE sau IP" placeholder="Căutare după termen, CVE sau IP..." oninput="filterCards()">
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
setInterval(() => {{ if (!document.getElementById('searchInput').value) location.reload(); }}, 600000);
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
# 2) GENERATOR EMAIL MOBILE-BULLETPROOF
# ==========================================

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
                                        Sincronizat la: {now_ro_str} &bull; {SOURCES_LABEL}
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
                            Generat automat de motorul Cyber Security Intelligence v4.8 &bull; Toate drepturile rezervate.
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
    lines = [f"RAPORT ZILNIC CYBER SECURITY INTELLIGENCE ({SOURCES_LABEL.upper()})", "=" * 55, ""]
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
    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    email_to_raw = os.getenv("EMAIL_TO")

    if not all([smtp_server, smtp_user, smtp_password, email_to_raw]):
        print("[!] Variabilele de mediu SMTP nu sunt complet configurate. Email-ul nu a fost trimis.")
        return False

    email_to_list = [addr.strip() for addr in email_to_raw.split(",") if addr.strip()]
    if not email_to_list:
        return False

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
        return True
    except Exception as e:
        print(f"[!] Eroare trimitere email: {e}")
        return False

def _alert_id(art):
    return art['link'] if art['link'] != '#' else f"{art['source']}::{art['title']}"

def select_push_alerts(categorized, cache, now_utc):
    """Alerte noi (necunoscute încă) cu scor >= NTFY_MIN_SCORE din categoriile targeted/critical.
    La prima rulare doar „însămânțează” lista, ca să nu primești zeci de notificări deodată."""
    notified = cache.setdefault('notified', {})
    first_run = not notified and not cache.get('notified_seeded')
    candidates = [a for k in ('targeted', 'critical') for a in categorized[k]
                  if a.get('risk_score', 0) >= NTFY_MIN_SCORE
                  and not (a.get('no_push') and not a.get('is_targeted_infra'))]
    fresh = [a for a in candidates if _alert_id(a) not in notified]
    for a in fresh:
        notified[_alert_id(a)] = now_utc.isoformat()
    for k in [k for k, v in notified.items() if _age_hours(v, now_utc) > LONG_WINDOW_HOURS]:
        del notified[k]
    cache['notified_seeded'] = True
    if first_run:
        print(f"[*] ntfy: prima rulare, {len(fresh)} alerte marcate ca deja cunoscute (fără notificări).")
        return []
    return sorted(fresh, key=lambda a: a.get('risk_score', 0), reverse=True)

def send_push(alerts):
    topic = os.getenv("NTFY_TOPIC")
    if not topic or not alerts:
        return False
    server = os.getenv("NTFY_SERVER", "https://ntfy.sh").rstrip("/")
    sent = 0
    for art in alerts[:NTFY_MAX_PER_RUN]:
        payload = {
            "topic": topic,
            "title": f"[{art.get('risk_score', 0)}] {art['source']}"[:100],
            "message": art['title'][:300],
            "priority": 4 if art.get('risk_score', 0) >= 100 else 3,
            "tags": ["rotating_light"] if art.get('is_targeted_infra') else ["warning"],
        }
        if art['link'] != '#':
            payload["click"] = art['link']
        try:
            req = urllib.request.Request(server, data=json.dumps(payload).encode("utf-8"),
                                         headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=10):
                sent += 1
        except Exception as e:
            print(f"[!] Eroare ntfy: {type(e).__name__}: {e}")
    extra = len(alerts) - NTFY_MAX_PER_RUN
    if extra > 0:
        print(f"[*] ntfy: încă {extra} alerte noi nu au fost trimise individual (limită {NTFY_MAX_PER_RUN}/rulare).")
    print(f"[+] ntfy: {sent} notificări trimise.")
    return sent > 0

def should_send_email(cache, now_ro):
    """Un singur email pe zi, la prima rulare de după 08:00 (ora RO) — nu depinde de minutul exact al rulării."""
    if os.getenv("FORCE_EMAIL", "false").lower() == "true":
        return True
    if cache.get('last_email_date') == now_ro.strftime('%Y-%m-%d'):
        return False
    return now_ro.hour >= 8

if __name__ == "__main__":
    print("[*] Rulare motor Cyber Security Intelligence v4.8 Enterprise Hub...")
    categorized_data = fetch_and_filter()
    saved_path = build_web_dashboard(categorized_data)
    print(f"[+] Dashboard web generat cu succes la: {saved_path}")

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_ro = datetime.datetime.now(TZ_RO)
    run_cache = LAST_CACHE

    send_push(select_push_alerts(categorized_data, run_cache, now_utc))

    if should_send_email(run_cache, now_ro):
        print("[*] Se inițiază trimiterea email-ului de notificare (corp dedicat, independent de index.html)...")
        if send_email(categorized_data):
            run_cache['last_email_date'] = now_ro.strftime('%Y-%m-%d')
    save_cache(run_cache)
