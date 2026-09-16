import concurrent.futures
import html
import json
import os
import re
import xml.etree.ElementTree as ET
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Expresie regulată pentru identificarea codurilor CVE
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# ==============================================================================
# CONFIGURARE SURSE CYBER SECURITY INTELLIGENCE (40+ SURSE)
# ==============================================================================
FEEDS_CONFIG = [
    # --- SURSE ROMÂNIA (DNSC / CERT-RO) ---
    {"name": "DNSC - Alerte", "urls": ["https://dnsc.ro/feed", "https://www.dnsc.ro/feed"], "type": "xml"},
    {"name": "CERT-RO / DNSC Blog", "urls": ["https://dnsc.ro/citeste/feed", "https://www.dnsc.ro/citeste/feed"], "type": "xml"},
    {"name": "DNSC - Știri", "urls": ["https://dnsc.ro/stiri/feed", "https://www.dnsc.ro/stiri/feed"], "type": "xml"},

    # --- GUVERNAMENTAL / CERT INTERNAȚIONAL ---
    {"name": "CISA - Cybersecurity Advisories", "urls": ["https://www.cisa.gov/cybersecurity-advisories/all.xml", "https://www.cisa.gov/uscert/ncas/alerts.xml"], "type": "xml"},
    {"name": "CISA - Current Activity", "urls": ["https://www.cisa.gov/news.xml", "https://www.cisa.gov/uscert/ncas/current-activity.xml"], "type": "xml"},
    {"name": "NVD NIST - Recent CVEs", "urls": ["https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=20"], "type": "json"},
    {"name": "ENISA - News & Press", "urls": ["https://www.enisa.europa.eu/media/news-items/news-rss"], "type": "xml"},
    {"name": "CERT-EU - Publications", "urls": ["https://www.cert.europa.eu/publications/feed/"], "type": "xml"},

    # --- THREAT INTELLIGENCE & RESEARCH ---
    {"name": "The Hacker News", "urls": ["https://feeds.feedburner.com/TheHackersNews"], "type": "xml"},
    {"name": "BleepingComputer", "urls": ["https://www.bleepingcomputer.com/feed/"], "type": "xml"},
    {"name": "Krebs on Security", "urls": ["https://krebsonsecurity.com/feed/"], "type": "xml"},
    {"name": "Dark Reading", "urls": ["https://www.darkreading.com/rss.xml"], "type": "xml"},
    {"name": "Threatpost", "urls": ["https://threatpost.com/feed/"], "type": "xml"},
    {"name": "SecurityWeek", "urls": ["https://www.securityweek.com/feed/"], "type": "xml"},
    {"name": "Schneier on Security", "urls": ["https://www.schneier.com/feed/atom/"], "type": "xml"},
    {"name": "SANS ISC InfoSec Today", "urls": ["https://isc.sans.edu/rssfeed.xml"], "type": "xml"},
    {"name": "Naked Security (Sophos)", "urls": ["https://news.sophos.com/en-us/category/naked-security/feed/"], "type": "xml"},
    {"name": "Sophos News", "urls": ["https://news.sophos.com/en-us/feed/"], "type": "xml"},
    {"name": "Trend Micro - Security News", "urls": ["https://www.trendmicro.com/rss/index.xml", "https://feeds.feedburner.com/TrendMicroSecurityNews"], "type": "xml"},
    {"name": "Malwarebytes Labs", "urls": ["https://www.malwarebytes.com/blog/feed/index.xml"], "type": "xml"},

    # --- VENDORI & INFRASTRUCTURĂ ---
    {"name": "cPanel News", "urls": ["https://news.cpanel.com/feed/"], "type": "xml"},
    {"name": "Windows IT Pro Blog", "urls": ["https://techcommunity.microsoft.com/plugins/custom/blogs/products/Windows-ITPro/rss"], "type": "xml"},
    {"name": "Microsoft Security Response Center (MSRC)", "urls": ["https://msrc.microsoft.com/blog/feed"], "type": "xml"},
    {"name": "Cisco Talos Intelligence", "urls": ["https://blog.talosintelligence.com/rss/"], "type": "xml"},
    {"name": "Unit 42 (Palo Alto Networks)", "urls": ["https://unit42.paloaltonetworks.com/feed/"], "type": "xml"},
    {"name": "CrowdStrike Blog", "urls": ["https://www.crowdstrike.com/blog/feed/"], "type": "xml"},
    {"name": "Mandiant / Google Cloud Security", "urls": ["https://cloud.google.com/blog/products/identity-security/rss/"], "type": "xml"},
    {"name": "Fortinet FortiGuard Labs", "urls": ["https://www.fortinet.com/blog/rss.xml"], "type": "xml"},
    {"name": "Kaspersky Securelist", "urls": ["https://securelist.com/feed/"], "type": "xml"},
    {"name": "Check Point Research", "urls": ["https://research.checkpoint.com/feed/"], "type": "xml"},
    {"name": "ESET WeLiveSecurity", "urls": ["https://www.welivesecurity.com/feed/"], "type": "xml"},
    {"name": "Rapid7 Blog", "urls": ["https://blog.rapid7.com/rss/"], "type": "xml"},
    {"name": "Qualys Security Blog", "urls": ["https://blog.qualys.com/feed"], "type": "xml"},

    # --- TECH, HARDWARE & VULNERABILITĂȚI ---
    {"name": "Ars Technica - Security", "urls": ["https://feeds.arstechnica.com/arstechnica/security"], "type": "xml"},
    {"name": "ZDNet Security", "urls": ["https://www.zdnet.com/topic/security/rss.xml"], "type": "xml"},
    {"name": "Register Security", "urls": ["https://www.theregister.com/security/headlines.atom"], "type": "xml"},
    {"name": "Cisco Security Advisories", "urls": ["https://sec.cloudapps.cisco.com/security/center/psirtrss20/ciscosecurityadvisories.xml"], "type": "xml"},
    {"name": "GitHub Security Advisories", "urls": ["https://github.com/advisories.atom"], "type": "xml"},
    {"name": "CVE Details Recent", "urls": ["https://www.cvedetails.com/vulnerability-list-rss.php"], "type": "xml"},
    {"name": "Google Project Zero", "urls": ["https://googleprojectzero.blogspot.com/feeds/posts/default"], "type": "xml"},
    {"name": "PortSwigger Web Security", "urls": ["https://portswigger.net/daily-swig/rss"], "type": "xml"},
]

# ==============================================================================
# MOTOR FETCH & PARSARE
# ==============================================================================

def fetch_raw_data(urls: list, timeout: int = 12) -> tuple[str, str]:
    """Descarcă securizat datele folosind User-Agent complet pentru a evita blocajele 403."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,json;q=0.8,*/*;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9,ro;q=0.8'
    }

    for url in urls:
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=timeout) as response:
                content = response.read().decode('utf-8', errors='replace')
                if content:
                    return content, url
        except Exception:
            continue

    return "", ""

def clean_and_parse_xml(raw_xml: str):
    """Epurare avansată XML pentru a elimina erorile de tip 'not well-formed (invalid token)'."""
    if not raw_xml:
        return None

    # Înlocuiește ampersand-urile izolate cu &amp;
    sanitized = re.sub(r"&(?!amp;|lt;|gt;|apos;|quot;|#\d+;)", "&amp;", raw_xml)
    # Elimină caracterele de control ASCII invalide
    sanitized = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", sanitized)

    try:
        return ET.fromstring(sanitized)
    except ET.ParseError:
        try:
            # Tăiere blocuri problematice (e.g. CDATA neînchise sau script-uri)
            sanitized = re.sub(r"<script.*?>.*?</script>", "", sanitized, flags=re.DOTALL)
            return ET.fromstring(sanitized)
        except ET.ParseError:
            return None

def parse_json_feed(raw_json: str) -> list:
    """Extract de date din feed-uri JSON (e.g. NVD API v2)."""
    articles = []
    try:
        data = json.loads(raw_json)
        if "vulnerabilities" in data:
            for item in data["vulnerabilities"][:10]:
                cve_id = item.get("cve", {}).get("id", "CVE Unknown")
                descriptions = item.get("cve", {}).get("descriptions", [])
                desc = descriptions[0].get("value", "") if descriptions else ""
                title = f"{cve_id}: {desc[:120]}..." if desc else cve_id
                link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                articles.append({"title": title, "link": link})
    except Exception:
        pass
    return articles

def process_single_feed(feed_info: dict) -> list:
    """Procesează un singur feed și returnează articolele extras."""
    source_name = feed_info["name"]
    raw_data, _ = fetch_raw_data(feed_info["urls"])

    if not raw_data:
        print(f"[!] Eroare/Timeout la sursa '{source_name}'")
        return []

    articles = []

    if feed_info["type"] == "json" or raw_data.strip().startswith("{"):
        parsed_articles = parse_json_feed(raw_data)
        for a in parsed_articles:
            a["source"] = source_name
            articles.append(a)
    else:
        xml_root = clean_and_parse_xml(raw_data)
        if xml_root is not None:
            # Căutare compatibilă RSS (<item>) și Atom (<entry>)
            items = xml_root.findall(".//item")
            if not items:
                items = xml_root.findall(".//{http://www.w3.org/2005/Atom}entry")

            for item in items[:6]:  # Păstrăm cele mai recente 6 articole/feed
                title_node = item.find("title")
                title = title_node.text.strip() if title_node is not None and title_node.text else "Titlu Lipsă"

                link_node = item.find("link")
                link = "#"
                if link_node is not None:
                    link = link_node.text or link_node.attrib.get("href", "#")

                articles.append({"title": title, "link": link, "source": source_name})

    return articles

# ==============================================================================
# FORMATARE VIZUALĂ & RENDER
# ==============================================================================

def format_cve(text: str) -> str:
    """Formatare fără riscuri a codurilor CVE folosind lambda (rezolvă re.error: invalid group reference 1)."""
    if not text:
        return ""
    escaped_text = html.escape(text)
    return RE_CVE.sub(
        lambda m: f'<a href="https://nvd.nist.gov/vuln/detail/{m.group(0)}" target="_blank" class="cve-badge">{m.group(0)}</a>',
        escaped_text
    )

def generate_cards_html(items: list, card_class: str) -> str:
    html_out = []
    for art in items:
        title_formatted = format_cve(art.get("title", "Fără Titlu"))
        link = art.get("link", "#")
        source = art.get("source", "Sursă Necunoscută")

        card_html = f"""
        <div class="card {card_class}">
            <h3><a href="{link}" target="_blank">{title_formatted}</a></h3>
            <span class="source-tag">{html.escape(source)}</span>
        </div>
        """
        html_out.append(card_html)
    return "\n".join(html_out)

def build_web_dashboard(categorized_data: dict) -> str:
    targeted_html = generate_cards_html(categorized_data.get("targeted", []), "targeted-card")
    general_html = generate_cards_html(categorized_data.get("general", []), "general-card")

    dashboard_template = f"""<!DOCTYPE html>
<html lang="ro">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cyber Security Intelligence Dashboard</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 20px; background-color: #0f172a; color: #f8fafc; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        h2 {{ color: #94a3b8; margin-top: 30px; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; margin-top: 15px; }}
        .card {{ background: #1e293b; padding: 18px; border-radius: 8px; border: 1px solid #334155; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
        .targeted-card {{ border-left: 4px solid #ef4444; }}
        .general-card {{ border-left: 4px solid #3b82f6; }}
        a {{ color: #f1f5f9; text-decoration: none; font-weight: 500; }}
        a:hover {{ color: #38bdf8; text-decoration: underline; }}
        .cve-badge {{ background-color: #dc2626; color: #ffffff; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 0.85em; font-family: monospace; }}
        .source-tag {{ display: block; margin-top: 12px; font-size: 0.8em; color: #64748b; font-weight: 600; text-transform: uppercase; }}
    </style>
</head>
<body>
    <h1>Cyber Security Intelligence v4.7</h1>
    <h2>Alerte Criticale, CVE-uri & Amenințări Țintite</h2>
    <div class="grid">
        {targeted_html if targeted_html else "<p>Nicio alertă critică detectată în această sesiune.</p>"}
    </div>
    <h2>Flux General de Securitate Cibernetică</h2>
    <div class="grid">
        {general_html if general_html else "<p>Nu s-au putut încărca știri generale.</p>"}
    </div>
</body>
</html>
"""
    output_path = "index.html"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(dashboard_template)
    
    return output_path

# ==============================================================================
# ENTRY POINT
# ==============================================================================

def main():
    print("[*] Rulare motor Cyber Security Intelligence v4.7...")
    print("[*] Rulare manuală detectată (workflow_dispatch): se resetează cache-ul HTTP.")
    print(f"[*] Se procesează paralel un total de {len(FEEDS_CONFIG)} surse de securitate...")

    categorized_data = {"targeted": [], "general": []}
    all_articles = []

    # Descărcare și parsare în paralel (15 fire de execuție)
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        results = executor.map(process_single_feed, FEEDS_CONFIG)
        for res in results:
            all_articles.extend(res)

    # Clasificare automată
    for article in all_articles:
        if RE_CVE.search(article["title"]) or any(k in article["source"].lower() for k in ["cisa", "dnsc", "alert", "advisories", "nvd"]):
            categorized_data["targeted"].append(article)
        else:
            categorized_data["general"].append(article)

    saved_path = build_web_dashboard(categorized_data)
    print(f"[*] Finalizat cu succes! Procesate: {len(all_articles)} articole. Dashboard generat la: {saved_path}")

if __name__ == "__main__":
    main()
