import importlib.util, datetime, os, json, urllib.error
os.environ.pop("NTFY_TOPIC", None)
spec = importlib.util.spec_from_file_location("d", "digest.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
now = datetime.datetime.now(datetime.timezone.utc)

def rfc(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S +0000")

def feed(items):
    x = "".join(
        f"<item><title>{t}</title><link>https://ex.com/{t.replace(' ', '-')}</link><description>{desc}</description>"
        f"<pubDate>{rfc(now - datetime.timedelta(hours=h))}</pubDate></item>"
        for (t, desc, h) in items)
    return f"<rss><channel>{x}</channel></rss>".encode()

FEEDS = {
    "https://www.crowdstrike.com/blog/feed/": feed([("CrowdStrike Named a Leader in IDC MarketScape", "an AI pen testing tool named ARTEX", 2)]),
    "https://www.androidauthority.com/feed/": feed([("Pixel wallpaper picks", "fun", 1), ("Android patches CVE-2026-1111 vulnerability", "x", 1)]),
    "https://www.tomshardware.com/feeds/all": feed([("Doom on a camera", "fun", 1)]),
    "https://www.bleepingcomputer.com/feed/": feed([("Critical RCE in Joomla actively exploited", "unauthenticated remote code execution", 1)]),
    "https://developer.joomla.org/security-centre.feed?type=rss": feed([("Joomla 5.9 security release", "joomla core fix", 100)]),
    "https://dnsc.ro/rss/alerte.xml": "HTTP403",
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml": "HTTP404",
}
CALLS = {}

def fake_fetch(url, headers, timeout):
    CALLS[url] = CALLS.get(url, 0) + 1
    v = FEEDS.get(url, "HTTP404")
    if v == "HTTP403":
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
    if v == "HTTP404":
        raise urllib.error.HTTPError(url, 404, "nf", {}, None)
    if v == "FLAKY":
        raise TimeoutError("timeout")
    return v, '"etag1"', None, 200

d._fetch_url_with_retry = fake_fetch
NAMES = {
    "https://www.crowdstrike.com/blog/feed/": "CrowdStrike Blog",
    "https://www.androidauthority.com/feed/": "Android Authority",
    "https://www.tomshardware.com/feeds/all": "Tom's Hardware",
    "https://www.bleepingcomputer.com/feed/": "BleepingComputer",
    "https://developer.joomla.org/security-centre.feed?type=rss": "Joomla Security Announcements",
    "https://dnsc.ro/rss/alerte.xml": "Test 403 Source",
    "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml": "Test 404 Source",
}
d.RSS_SOURCES[:] = [{"name": n, "url": u, "priority": 80} for u, n in NAMES.items()]
print("sources under test:", len(d.RSS_SOURCES))
d.MAX_THREADS = 4

res = d.fetch_and_filter()
titles = {k: [a['title'] for a in v] for k, v in res.items()}
print(json.dumps(titles, indent=1))
allt = sum(titles.values(), [])
assert "Pixel wallpaper picks" not in allt and "Doom on a camera" not in allt, "noise not filtered"
assert "Android patches CVE-2026-1111 vulnerability" in allt, "real android security item dropped"
assert not any("Named a Leader" in t for t in titles['targeted']), "false positive 'named' still targeted"
assert "Critical RCE in Joomla actively exploited" in titles['targeted']
assert "Joomla 5.9 security release" in allt, "long-window source lost"
h = d.LAST_CACHE['feed_health']
print("health:", h)
assert h['ok'] == 5 and h['total'] == 7 and len(h['failed']) == 2
assert CALLS["https://dnsc.ro/rss/alerte.xml"] == 1, "403 must not be retried"
print("label:", d.SOURCES_LABEL)

# second run: flaky source falls back to cached items
FEEDS["https://www.bleepingcomputer.com/feed/"] = "FLAKY"
d.FEED_HEALTH.clear()
res2 = d.fetch_and_filter()
t2 = sum([[a['title'] for a in v] for v in res2.values()], [])
assert "Critical RCE in Joomla actively exploited" in t2, "stale fallback failed"
print("stale fallback OK; failed:", list(d.LAST_CACHE['feed_health']['failed']))

# push logic
cache = d.LAST_CACHE
cache.pop('notified', None)
cache.pop('notified_seeded', None)
assert d.select_push_alerts(res2, cache, now) == [], "first run must only seed"
d.save_cache(cache)  # main() does this at the end of each run
FEEDS["https://www.bleepingcomputer.com/feed/"] = feed([
    ("Critical RCE in Joomla actively exploited", "unauthenticated remote code execution", 1),
    ("Zero-day RCE in cPanel exploited in the wild", "critical remote code execution cpanel", 0)])
d.FEED_HEALTH.clear()
res3 = d.fetch_and_filter()
a = d.select_push_alerts(res3, d.LAST_CACHE, now)
print("push candidates:", [x['title'] for x in a])
assert [x['title'] for x in a] == ["Zero-day RCE in cPanel exploited in the wild"]
d.save_cache(d.LAST_CACHE)
d.FEED_HEALTH.clear(); res4 = d.fetch_and_filter()
assert d.select_push_alerts(res4, d.LAST_CACHE, now) == [], "must not re-notify"

sent = []

class R:
    def __enter__(self): return self
    def __exit__(self, *x): pass

def fake_urlopen(req, timeout=0):
    sent.append(json.loads(req.data))
    return R()

d.urllib.request.urlopen = fake_urlopen
os.environ["NTFY_TOPIC"] = "t-test"
assert d.send_push(a) and sent[0]["topic"] == "t-test" and sent[0]["click"].startswith("https://")
print("ntfy payload:", sent[0])

# email schedule
def ro(h, date="2026-10-08"):
    return datetime.datetime.fromisoformat(f"{date}T{h:02d}:30:00").replace(tzinfo=d.TZ_RO)

os.environ.pop("FORCE_EMAIL", None)
c = {}
assert not d.should_send_email(c, ro(7))
assert d.should_send_email(c, ro(8)) and d.should_send_email(c, ro(13))
c['last_email_date'] = "2026-10-08"
assert not d.should_send_email(c, ro(13))
assert d.should_send_email(c, ro(8, "2026-10-09"))
os.environ["GITHUB_EVENT_NAME"] = "workflow_dispatch"
assert not d.should_send_email(c, ro(13)), "dispatch must not force email"

# dashboard renders
p = d.build_web_dashboard(res3)
html = open(p, encoding="utf-8").read()
assert "surse active" in html and "location.reload" in html
print("ALL TESTS PASSED")
