import importlib.util, datetime, json, urllib.error, urllib.parse

spec = importlib.util.spec_from_file_location("d", "digest.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

utc = datetime.timezone.utc
now = datetime.datetime.now(utc)
today = now.strftime("%Y-%m-%d")
old = (now - datetime.timedelta(days=30)).strftime("%Y-%m-%d")

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-1111", "vendorProject": "Joomla", "product": "CMS", "vulnerabilityName": "Joomla RCE",
     "dateAdded": today, "shortDescription": "Remote code execution.", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2020-0001", "vendorProject": "Old", "product": "Thing", "vulnerabilityName": "Ancient bug",
     "dateAdded": old, "shortDescription": "Old.", "knownRansomwareCampaignUse": "Unknown"},
]}
NVD = {"vulnerabilities": [
    {"cve": {"id": "CVE-2026-2222", "published": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
             "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "Unauthenticated overflow in FooServer."}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
    {"cve": {"id": "CVE-2026-3333", "published": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
             "descriptions": [{"lang": "en", "value": "Bug in PHP interpreter allows code execution."}],
             "metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 9.3}}]}}},
]}

seen_urls = []
mode = {"kev_primary_fails": False, "all_fail": False}

def fake_fetch(url, headers, timeout):
    seen_urls.append(url)
    if mode["all_fail"]:
        raise urllib.error.HTTPError(url, 503, "down", {}, None)
    if "cisa.gov" in url:
        if mode["kev_primary_fails"]:
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
        return json.dumps(KEV).encode(), None, None, 200
    if "raw.githubusercontent.com" in url:
        return json.dumps(KEV).encode(), None, None, 200
    if "services.nvd.nist.gov" in url:
        return json.dumps(NVD).encode(), None, None, 200
    raise urllib.error.HTTPError(url, 404, "nf", {}, None)

d._fetch_url_with_retry = fake_fetch
d.RSS_SOURCES[:] = [s for s in d.RSS_SOURCES if s.get('type')]
assert len(d.RSS_SOURCES) == 2

# 1) KEV + NVD parsed and categorized
res = d.fetch_and_filter()
allarts = [a for v in res.values() for a in v]
titles = [a['title'] for a in allarts]
print(json.dumps(titles, indent=1, ensure_ascii=False))
assert any("CVE-2026-1111" in t for t in titles), "KEV recent item missing"
assert not any("CVE-2020-0001" in t for t in titles), "old KEV item must be excluded"
kev = next(a for a in allarts if "CVE-2026-1111" in a['title'])
assert kev['risk_score'] >= 100 and "ransomware" in kev['description'], kev
assert kev in res['targeted'], "Joomla KEV must be targeted"
nvd = next(a for a in allarts if "CVE-2026-2222" in a['title'])
assert "CVSS 9.8" in nvd['title'] and nvd['no_push'] and nvd['risk_score'] >= 70 and nvd in res['critical'], nvd
assert d.FEED_HEALTH["CISA - Known Exploited Vulnerabilities"]["ok"] and d.FEED_HEALTH["NVD NIST - Critical CVEs"]["ok"]

# 2) NVD request URL: encoded dates, window, severity filter
nvd_url = next(u for u in seen_urls if "nvd.nist.gov" in u)
q = urllib.parse.parse_qs(urllib.parse.urlparse(nvd_url).query)
assert q["cvssV3Severity"] == ["CRITICAL"] and q["pubStartDate"][0].endswith("+00:00") and q["pubEndDate"][0].endswith("+00:00"), nvd_url
print("nvd url ok:", nvd_url)

# 3) push excludes NVD-only items unless they hit our infrastructure (PHP one is targeted)
cache = d.LAST_CACHE
cache['notified_seeded'] = True
cache['notified'] = {}
cands = d.select_push_alerts(res, cache, now)
ids = [a['title'] for a in cands]
print("push:", ids)
assert any("CVE-2026-1111" in t for t in ids), "KEV targeted must push"
assert any("CVE-2026-3333" in t for t in ids), "NVD item that hits PHP (targeted) may push"
assert not any("CVE-2026-2222" in t for t in ids), "NVD non-targeted must not push"
d.save_cache(cache)

# 4) KEV primary 403 -> GitHub mirror fallback
mode["kev_primary_fails"] = True
seen_urls.clear(); d.FEED_HEALTH.clear()
res2 = d.fetch_and_filter()
assert any("raw.githubusercontent.com" in u for u in seen_urls), "mirror not tried"
assert d.FEED_HEALTH["CISA - Known Exploited Vulnerabilities"]["ok"]

# 5) everything down -> stale cache keeps items
mode["all_fail"] = True
d.FEED_HEALTH.clear()
res3 = d.fetch_and_filter()
t3 = [a['title'] for v in res3.values() for a in v]
assert any("CVE-2026-1111" in t for t in t3) and any("CVE-2026-2222" in t for t in t3), "stale fallback failed for JSON sources"
assert not d.FEED_HEALTH["NVD NIST - Critical CVEs"]["ok"] and d.FEED_HEALTH["NVD NIST - Critical CVEs"]["stale"] == 2
print("JSON SOURCE TESTS PASSED")
