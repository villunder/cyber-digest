"""Sondează URL-uri de feed (RSS/Atom/JSON) și raportează o linie per URL.
Rulat din .github/workflows/probe_feeds.yml, de pe runner-ul GitHub."""
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import defusedxml.ElementTree as ET

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
      'Chrome/124.0.0.0 Safari/537.36 CyberSecurityMonitor/4.8')
ATOM = "{http://www.w3.org/2005/Atom}"

CANDIDATES = [
    # --- înlocuiri pentru surse căzute ---
    ("CISA ICS advisories", "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"),
    ("CISA KEV (GitHub cisagov)", "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"),
    ("CISA KEV (cisa.gov)", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
    ("NVD API 2.0", "https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=CRITICAL&resultsPerPage=5"),
    ("ENISA news", "https://www.enisa.europa.eu/news/enisa-news/RSS"),
    ("ENISA alt", "https://www.enisa.europa.eu/rss.xml"),
    ("CERT-EU advisories", "https://cert.europa.eu/publications/security-advisories-rss"),
    ("CERT-EU threat intel", "https://cert.europa.eu/publications/threat-intelligence-rss"),
    ("DNSC RSS alerte", "https://dnsc.ro/rss/alerte.xml"),
    ("DNSC feed alt", "https://dnsc.ro/feed"),
    ("DNSC citeste alerte", "https://dnsc.ro/citeste/feed"),
    ("Fortinet threat research", "https://feeds.fortinet.com/fortinet/blog/threat-research"),
    ("Symantec/Broadcom", "https://www.security.com/feed-threat-intelligence.xml"),
    ("Symantec alt", "https://www.security.com/feed-blog.xml"),
    ("SentinelOne Labs", "https://www.sentinelone.com/labs/feed/"),
    ("Zscaler security research", "https://www.zscaler.com/blogs/security-research/feed"),
    ("Trend Micro research", "https://feeds.trendmicro.com/TrendMicroResearch"),
    ("Sophos threat research", "https://news.sophos.com/en-us/category/threat-research/feed/"),
    ("AWS security blog", "https://aws.amazon.com/blogs/security/feed/"),
    ("AWS bulletins", "https://aws.amazon.com/security/security-bulletins/feed/"),
    ("Google Cloud threat intel", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    ("Mandiant blog", "https://www.mandiant.com/resources/blog/rss.xml"),
    ("cPanel security", "https://news.cpanel.com/category/security/feed/"),
    ("cPanel news", "https://news.cpanel.com/feed/"),
    ("OffSec blog", "https://www.offsec.com/blog/rss/"),
    ("Cyber.gov.au alerts", "https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/rss"),
    ("Qualys blog", "https://blog.qualys.com/feed"),
    ("Windows message center", "https://techcommunity.microsoft.com/t5/s/gxcr/rss/board?board.id=Windows-ITPro-blog"),
    # --- diversificare: surse de reputație înaltă ---
    ("CERT/CC vuln notes", "https://kb.cert.org/vuls/atomfeed/"),
    ("Ubuntu Security Notices", "https://ubuntu.com/security/notices/rss.xml"),
    ("Debian Security Advisories", "https://www.debian.org/security/dsa"),
    ("Red Hat Security", "https://access.redhat.com/blogs/product-security/feed"),
    ("Chrome Releases", "https://chromereleases.googleblog.com/feeds/posts/default"),
    ("Mozilla Security Blog", "https://blog.mozilla.org/security/feed/"),
    ("Apple developer releases", "https://developer.apple.com/news/releases/rss/releases.rss"),
    ("MSRC blog", "https://msrc.microsoft.com/blog/feed"),
    ("Zero Day Initiative", "https://www.zerodayinitiative.com/rss/published/"),
    ("Citizen Lab", "https://citizenlab.ca/feed/"),
    ("The Record (Recorded Future)", "https://therecord.media/feed"),
    ("Proofpoint threat insight", "https://www.proofpoint.com/us/rss.xml"),
    ("Elastic Security Labs", "https://www.elastic.co/security-labs/rss/feed.xml"),
    ("Bitdefender Labs", "https://www.bitdefender.com/en-us/blog/labs/feed/"),
    ("watchTowr Labs", "https://labs.watchtowr.com/rss/"),
    ("Huntress blog", "https://www.huntress.com/blog/rss.xml"),
    ("Volexity blog", "https://www.volexity.com/blog/feed/"),
    ("FDA med-device safety", "https://www.fda.gov/about-fda/contact-fda/stay-informed/rss-feeds/medical-device-safety/rss.xml"),
    ("HHS 405(d)/HC3", "https://www.hhs.gov/sites/default/files/rss/hc3.xml"),
    ("Health-ISAC", "https://health-isac.org/feed/"),
    ("PHP releases", "https://www.php.net/releases/feed.php"),
    ("Roundcube news", "https://roundcube.net/news/feed/"),
    ("Apache Tomcat security", "https://tomcat.apache.org/security.html"),
    ("MariaDB blog", "https://mariadb.org/feed/"),
    ("Exim announce", "https://lists.exim.org/lurker/rss/exim-announce.en.rss"),
    ("Joomla security (control)", "https://developer.joomla.org/security-centre.feed?type=rss"),
    ("Wordfence (control)", "https://www.wordfence.com/feed/"),
]


def _text(node):
    return (node.text or "").strip() if node is not None else ""


def probe(item):
    name, url = item
    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15, context=ssl.create_default_context()) as r:
            body = r.read()
            ctype = (r.headers.get("Content-Type") or "").split(";")[0]
            final = r.geturl()
            code = r.status
    except urllib.error.HTTPError as e:
        return f"FAIL | {name} | HTTP {e.code} | {url}"
    except Exception as e:
        return f"FAIL | {name} | {type(e).__name__}: {str(e)[:60]} | {url}"
    ms = int((time.time() - t0) * 1000)
    kind, n, newest = "?", 0, ""
    try:
        if body.lstrip()[:1] in (b"{", b"["):
            data = json.loads(body)
            kind = "JSON"
            if isinstance(data, dict):
                n = len(data.get("vulnerabilities", data.get("items", [])))
        else:
            root = ET.fromstring(body)
            items = root.findall(".//item") or root.findall(f".//{ATOM}entry")
            n = len(items)
            kind = "ATOM" if items and items[0].tag.startswith(ATOM) else "RSS"
            if items:
                d = items[0].find("pubDate")
                if d is None:
                    d = items[0].find(f"{ATOM}updated")
                if d is None:
                    d = items[0].find(f"{ATOM}published")
                newest = _text(d)[:25]
    except Exception as e:
        return f"BAD  | {name} | {code} {ctype} parse: {str(e)[:50]} | {len(body)}B | {final}"
    redirect = "" if final == url else f" -> {final}"
    status = "OK  " if n > 0 or kind == "JSON" else "EMPTY"
    return f"{status} | {name} | {kind} items={n} newest={newest} {ms}ms{redirect} | {url}"


if __name__ == "__main__":
    with ThreadPoolExecutor(8) as ex:
        results = list(ex.map(probe, CANDIDATES))
    for line in results:
        print(line)
    ok = sum(1 for r in results if r.startswith("OK"))
    print(f"SUMMARY: {ok}/{len(results)} OK", flush=True)
    sys.exit(0)
