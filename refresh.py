#!/usr/bin/env python3
"""Auto-refresh (dijalankan di VPS via cron).

1. Re-harvest famili mall yg ada JSON/HTML endpoint stabil (best-effort;
   kalau gagal, KEKAL fail harvest sedia ada — tak pernah rosakkan data).
2. Kosongkan cache MyeHalal (utk tangkap perubahan sijil), re-check semua outlet.
3. Tulis data.json terus ke laman (/opt/halal-tracker/data.json).

Mall tanpa handler di sini kekal senarai terakhir; status halal tetap di-refresh.
"""
import re, json, os, sys, subprocess, html, urllib.parse

BASE = os.path.dirname(os.path.abspath(__file__))
HARVEST = os.path.join(BASE, "harvest")
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"


def curl(url, referer=None, timeout=40):
    args = ["curl", "-sS", "--max-time", str(timeout), "-A", UA]
    if referer:
        args += ["-e", referer]
    args.append(url)
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout + 10).stdout


# ── Handlers: pulangkan [{name, lot}] atau raise kalau gagal ──────────────

def h_sunway(host):
    ref = f"https://{host}/directory"
    out, off = [], 0
    while True:
        body = curl(f"https://{host}/api/directory/live/v1/public/shops/list-paged"
                    f"?refcode=FOOD_BEVERAGES&offset={off}&limit=100", ref)
        j = json.loads(body)
        items = j.get("docs") or j.get("data") or j.get("items") or j.get("results") or []
        if not items:
            break
        for it in items:
            nm = (it.get("title") or it.get("name") or "").strip()
            if nm:
                out.append({"name": nm, "lot": (it.get("venue") or it.get("unit") or None)})
        if len(items) < 100:
            break
        off += 100
        if off > 2000:
            break
    if not out:
        raise ValueError("sunway: kosong")
    return out


def h_imago():
    body = curl("https://app-api.imago.my/api/brands/?page=1&page_size=500")
    arr = json.loads(body)
    out = [{"name": (x.get("displayName") or "").strip(), "lot": (x.get("unitNo") or None)}
           for x in arr if x.get("category") == "foodAndBeverage" and x.get("displayName")]
    if not out:
        raise ValueError("imago: kosong")
    return out


def h_ipc():
    # F&B = ?cat=27; senarai server-rendered: <p class="pull-left">NAMA</p><span class="pull-right">LOT</span>
    body = curl("https://www.ipc.com.my/store-guide/a-z-directory/?cat=27",
                "https://www.ipc.com.my/store-guide/a-z-directory/")
    out, seen = [], set()
    for m in re.finditer(r'<p class="pull-left">(.*?)</p>\s*<span class="pull-right">(.*?)</span>', body, re.S):
        name = re.sub(r"<[^>]+>", "", html.unescape(m.group(1))).strip()
        lot = re.sub(r"<[^>]+>", "", html.unescape(m.group(2))).strip()
        k = name.lower()
        if not name or k in seen:
            continue
        seen.add(k)
        out.append({"name": name, "lot": lot or None})
    if not out:
        raise ValueError("ipc: kosong")
    return out


def h_aeon(slug):
    body = curl(f"https://aeonmallmy.com/page/mall/{slug}")
    # <li class="tenant" data-category="food-baverages|fnb" data-name="..."> ... <h3 class="text-primary">LOT</h3>
    out = []
    for m in re.finditer(r'<li[^>]*class="tenant"[^>]*data-category="([^"]*)"[^>]*data-name="([^"]*)"(.*?)</li>',
                         body, re.S):
        cat, name, blob = m.group(1), html.unescape(m.group(2)).strip(), m.group(3)
        if not re.search(r"food|fnb|beverage", cat, re.I):
            continue
        lm = re.search(r'text-primary[^>]*>([^<]+)<', blob)
        out.append({"name": name, "lot": (lm.group(1).strip() if lm else None)})
    if not out:
        raise ValueError(f"aeon {slug}: kosong")
    return out


# mall slug -> (handler, args)
HANDLERS = {
    "sunway_pyramid":       (h_sunway, ["www.sunwaypyramid.com"]),
    "sunway_velocity_mall": (h_sunway, ["www.sunwayvelocitymall.com"]),
    "sunway_carnival_mall": (h_sunway, ["www.sunwaycarnival.com"]),
    "sunway_putra_mall":    (h_sunway, ["www.sunwayputramall.com"]),
    "imago_shopping_mall":  (h_imago, []),
    "ipc_shopping_centre":  (h_ipc, []),
    "aeon_tebrau_city":     (h_aeon, ["aeon-mall-tebrau-city"]),
    "aeon_mall_kota_bharu": (h_aeon, ["aeon-mall-kota-bharu"]),
    "aeon_seremban_2":      (h_aeon, ["aeon-mall-seremban-2"]),
    "aeon_mall_kinta_city": (h_aeon, ["aeon-mall-kinta-city"]),
    "aeon_bukit_tinggi":    (h_aeon, ["aeon-mall-bukit-tinggi"]),
}


def reharvest():
    for slug, (fn, args) in HANDLERS.items():
        path = os.path.join(HARVEST, f"{slug}.json")
        if not os.path.exists(path):
            continue
        doc = json.load(open(path))
        try:
            outlets = fn(*args)
            doc["outlets"] = outlets
            doc["count"] = len(outlets)
            json.dump(doc, open(path, "w"), indent=1, ensure_ascii=False)
            print(f"  re-harvest {slug}: {len(outlets)} outlet")
        except Exception as e:
            print(f"  re-harvest {slug}: GAGAL ({e}) -> kekal {doc.get('count')} lama", file=sys.stderr)


if __name__ == "__main__":
    print("1/3  Re-harvest famili endpoint stabil ...")
    reharvest()
    print("2/3  Re-check MyeHalal (TTL: nama lama sahaja) ...")
    r = subprocess.run(["./../venv/bin/python", "central_check.py"], cwd=BASE)
    if r.returncode != 0:
        sys.exit("central_check gagal")
    print("3/3  Tulis data.json ke laman ...")
    malls = []
    import glob
    for f in sorted(glob.glob(os.path.join(BASE, "stores", "*.json"))):
        d = json.load(open(f))
        if d["count"] == 0:
            continue
        malls.append({"mall": d["mall"], "directory_url": d.get("directory_url"), "count": d["count"],
                      "summary": d["summary"], "outlets": [{"name": o["name"], "lot": o.get("lot"),
                      "status": o["status"], "cert_holder": o.get("cert_holder")} for o in d["outlets"]]})
    malls.sort(key=lambda m: -m["count"])
    out = {"generated": "auto-refresh", "source": "JAKIM MyeHalal (kategori Premis Makanan)", "malls": malls}
    json.dump(out, open("/opt/halal-tracker/data.json", "w"), indent=2, ensure_ascii=False)
    print(f"SIAP: {len(malls)} mall, {sum(m['count'] for m in malls)} outlet -> /opt/halal-tracker/data.json")
