import importlib.util, datetime

spec = importlib.util.spec_from_file_location("d", "digest.py")
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

CASES = {
    "Thu, 08 Oct 2026 17:02:52 +0000": (2026, 10, 8, 17, 2),
    "Oct 08, 2026 00:00:00-0500": (2026, 10, 8, 5, 0),          # CrowdStrike, convertit în UTC
    "22 Sep 2026 11:00:00": (2026, 9, 22, 11, 0),                # fără fus => UTC
    "2026-10-07T13:00:00Z": (2026, 10, 7, 13, 0),
    "Tue, 06 Oct 2026 21:00:00 EDT": (2026, 10, 7, 1, 0),
}
for raw, (y, mo, dd, h, mi) in CASES.items():
    dt = d.parse_pub_date(raw)
    assert dt is not None, f"unparsed: {raw}"
    u = dt.astimezone(datetime.timezone.utc)
    assert (u.year, u.month, u.day, u.hour, u.minute) == (y, mo, dd, h, mi), (raw, u)
assert d.parse_pub_date("not a date") is None
print("DATE TESTS PASSED")
