#!/usr/bin/env python3
"""Pilot: senarai kedai F&B satu mall + status halal JAKIM (MyeHalal).

Aliran:
  1. Ambil senarai tenant F&B dari directory mall (IOI City Mall AJAX endpoint).
  2. Untuk setiap outlet, cari di portal rasmi JAKIM MyeHalal (kategori PE = Premis Makanan).
  3. Assign status 3-keadaan: certified / non_halal / uncertified.

Status TIDAK boleh "haram" semata sebab tiada sijil — tiada sijil = uncertified.
Padanan MyeHalal ikut substring nama, jadi kami simpan bilangan padanan +
pemegang sijil supaya manusia boleh sahkan. Ini pilot, bukan kebenaran mutlak.
"""
import re, sys, json, time, html, urllib.parse, subprocess, tempfile, os
import urllib.request as U

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"

# --- Sumber 1: directory F&B IOI City Mall (AJAX, halaman demi halaman) ---
IOI_REF = "https://www.ioicitymall.com.my/directory-icm/"
IOI_URL = ("https://www.ioicitymall.com.my/script/?html&osp=305&type=osp"
           "&mallcategory=foodnbeverage&malltagging=&catid=36&page={p}")

# --- Sumber 2: portal rasmi JAKIM MyeHalal (POST form, server-rendered) ---
MH_URL = ("https://myehalal.halal.gov.my/portal-halal/v1/index.php"
          "?data=ZGlyZWN0b3J5L2luZGV4X2RpcmVjdG9yeTs7Ozs=")  # directory/index_directory

# Nama yang jelas non-halal (jual khinzir/arak). Konservatif — hanya yang nyata.
NON_HALAL = re.compile(r"\b(bak\s*kut\s*teh|bkt|pork|char\s*siu|liquor|wine|beer|"
                       r"brewery|brewhouse|non[- ]halal|beerhouse)\b", re.I)


def http(url, data=None, headers=None, timeout=25):
    req = U.Request(url, data=data, headers={"User-Agent": UA, **(headers or {})})
    with U.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace").replace("\r", "")


def ioi_fnb_outlets(max_pages=15):
    """Pulangkan [{name, lot, pid}] semua tenant F&B, buang duplikat pid."""
    seen, out = set(), []
    for p in range(max_pages):
        try:
            body = http(IOI_URL.format(p=p), headers={"Referer": IOI_REF}, timeout=20)
        except Exception as e:
            print(f"  page {p}: ralat {e}", file=sys.stderr); break
        if not body.strip():
            break
        # setiap tenant: <a href="about-tenant/?pid=N"> ... NAMA ... LOT ...
        for m in re.finditer(r'about-tenant/\?pid=(\d+)">(.*?)(?=about-tenant/\?pid=|\Z)',
                             body, re.S):
            pid, blob = m.group(1), m.group(2)
            if pid in seen:
                continue
            texts = [html.unescape(t).strip()
                     for t in re.sub(r"<[^>]*>", "\n", blob).split("\n")
                     if t.strip()]
            if not texts:
                continue
            seen.add(pid)
            out.append({"name": texts[0],
                        "lot": texts[1] if len(texts) > 1 else None,
                        "pid": pid})
        time.sleep(0.3)
    return out


# Python urllib gagal TLS handshake dgn server gov; curl OK. Guna curl + cookie jar.
_MH_COOKIE = os.path.join(tempfile.gettempdir(), "myehalal_cookies.txt")


def _curl_post(url, fields, referer):
    args = ["curl", "-sS", "--max-time", "30", "-A", UA,
            "-c", _MH_COOKIE, "-b", _MH_COOKIE, "-e", referer]
    for k, v in fields.items():
        args += ["--data-urlencode", f"{k}={v}"]
    args.append(url)
    return subprocess.run(args, capture_output=True, text=True, timeout=40).stdout.replace("\r", "")


def _mh_query(q):
    """Satu POST ke MyeHalal. Pulangkan (count, holder|None)."""
    body = _curl_post(MH_URL, {"negeri": "", "category": "PE", "cari": q,
                               "hdnCounter": "21", "t": "", "a": "", "ty": ""}, MH_URL)
    m = re.search(r"Premis Makanan\((\d+)\)", body)
    count = int(m.group(1)) if m else 0
    h = re.search(r'class="company-name">(.*?)</span>', body, re.S)
    holder = re.sub(r"<[^>]*>", "", html.unescape(h.group(1))).strip() if h else None
    return count, holder


def _clean(name):
    q = re.sub(r"\s*[-–|(/].*$", "", name)     # buang selepas - ( / |
    q = re.sub(r"['’]s?\b", "", q)              # McDonald's -> McDonald
    q = re.sub(r"[®™&+]", " ", q)               # & pecahkan carian; buang simbol
    q = re.sub(r"[一-鿿]+", " ", q)     # buang aksara CJK
    return re.sub(r"\s+", " ", q).strip()


def myehalal_check(name):
    """Cari premis makanan bersijil, dgn fallback pendekkan query.
    Pulangkan (count, cert_holder|None, name_matched)."""
    q = _clean(name)
    if not q:
        return 0, None, False
    try:
        count, holder = _mh_query(q)
        # fallback: kalau 0 padanan & nama panjang, cuba 2 lalu 1 perkataan pertama.
        # hanya terima jika holder padan token brand (elak bunyi karut).
        # terima mana-mana padanan (classify letak dlm 'review' kalau holder tak padan)
        words = q.split()
        for n in (2,):
            if count > 0 or len(words) <= n:
                break
            short = " ".join(words[:n])
            if len(short) < 5:
                break
            c2, h2 = _mh_query(short)
            if c2 > 0:
                count, holder = c2, h2
    except Exception as e:
        return None, f"ralat: {e}", False
    return count, holder, _name_matches(name, holder)


# Kata generik yang WUJUD dalam banyak nama syarikat -> jangan kira sbg padanan
_STOP = {"CAFE", "CAFÉ", "RESTAURANT", "RESTORAN", "THE", "AND", "DAN", "KITCHEN",
         "HOUSE", "SHOP", "FOOD", "BEVERAGE", "BAR", "GRILL", "COFFEE", "TEA",
         "SDN", "BHD", "SENDIRIAN", "BERHAD", "GROUP", "ENTERPRISE", "TRADING",
         "MALAYSIA", "M", "SDN.", "BHD.", "FB", "ROTI", "NASI", "MEE", "AYAM"}


def _tokens(s):
    return {w for w in re.findall(r"[A-Za-z]{4,}", (s or "").upper()) if w not in _STOP}


def _name_matches(name, holder):
    """True jika pemegang sijil kongsi token bermakna dgn nama brand.
    Buang false positive: 'CAFE COLOMBO' vs 'CAFE PARADISO' -> tiada token sama."""
    if not holder:
        return False
    nt = _tokens(re.sub(r"\s*[-–|(].*$", "", name))
    return bool(nt & _tokens(holder))


def classify(name, mh_count, matched):
    if NON_HALAL.search(name):
        return "non_halal"
    if mh_count and mh_count > 0 and matched:
        return "certified"
    if mh_count and mh_count > 0:
        return "review"          # ada padanan tapi nama tak sepadan -> semak manual
    return "uncertified"


def main():
    print("1/2  Ambil senarai F&B IOI City Mall ...", file=sys.stderr)
    outlets = ioi_fnb_outlets()
    print(f"     {len(outlets)} outlet F&B dijumpai.", file=sys.stderr)

    print("2/2  Semak status halal JAKIM MyeHalal ...", file=sys.stderr)
    rows = []
    for i, o in enumerate(outlets, 1):
        cnt, holder, matched = myehalal_check(o["name"])
        status = classify(o["name"], cnt if isinstance(cnt, int) else 0, matched)
        rows.append({**o, "status": status, "myehalal_matches": cnt,
                     "cert_holder": holder, "name_matched": matched})
        print(f"     [{i}/{len(outlets)}] {o['name'][:28]:<28} -> {status} "
              f"({cnt} padanan)", file=sys.stderr)
        time.sleep(0.4)

    summary = {s: sum(r["status"] == s for r in rows)
               for s in ("certified", "review", "uncertified", "non_halal")}
    doc = {"mall": "IOI City Mall", "city": "Putrajaya",
           "source_directory": IOI_REF,
           "source_halal": "JAKIM MyeHalal (myehalal.halal.gov.my)",
           "note": "status 'uncertified' = tiada sijil JAKIM dijumpai, BUKAN bermaksud haram. "
                   "myehalal_matches = padanan substring, sahkan manual.",
           "count": len(rows), "summary": summary, "outlets": rows}
    out_path = "stores_ioi_city.json"
    json.dump(doc, open(out_path, "w"), indent=2, ensure_ascii=False)
    print(f"\nSiap -> {out_path} | {summary}", file=sys.stderr)


if __name__ == "__main__":
    main()
