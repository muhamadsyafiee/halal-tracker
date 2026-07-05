#!/usr/bin/env python3
"""Checker pusat: baca semua harvest/*.json, semak MyeHalal (dedup + cache),
hasilkan stores/<mall>.json + stores_all.json.

Guna semula myehalal_check() dari halal_pilot. Dedup nama merentas mall supaya
chain berulang (Starbucks, KFC, Marrybrown...) hanya di-query sekali.
"""
import os, re, json, glob, time, html
from halal_pilot import myehalal_check, classify, NON_HALAL

HARVEST = "harvest"
OUTDIR = "stores"
CACHE_FILE = "myehalal_cache.json"

# Bukan outlet makan/minum tunggal -> keluarkan (pasaraya, runcit pelbagai barang).
# Kekal: bakeri, dessert, coklat, aiskrim (makanan, relevan halal).
EXCLUDE = re.compile(
    r"\b(village grocer|jaya grocer|isetan foodmarket|cold storage|signature market|"
    r"ben.?s independent|b\.i\.g|mercato|jason.?s|hero market|lulu|giant|tesco|lotus.?s|"
    r"aeon (supermarket|big)|7-?eleven|family ?mart|\bcu\b|mynews|kk super|99 speed"
    r"mart|emart|grocer|supermarket|hypermarket|pasaraya|"
    r"tgv|\bgsc\b|cinema|cineplex|mbo cinema|lotus.?s|mix\.?store|"
    r"tsutaya|bookstore|book store|fruit shop|fruit lab|tropical fruit|"
    r"fruit addicts|\bmbg\b|unimart|\bbig\b pharmacy)\b", re.I)


def is_food_outlet(name):
    return not EXCLUDE.search(name or "")


def norm_key(name):
    n = html.unescape(name)
    n = re.sub(r"\s*[-–|(].*$", "", n)
    n = re.sub(r"['’]s?\b", "", n)
    return re.sub(r"\s+", " ", n).strip().upper()


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    cache = json.load(open(CACHE_FILE)) if os.path.exists(CACHE_FILE) else {}

    # fail utama (bukan *_extra.json)
    files = sorted(f for f in glob.glob(f"{HARVEST}/*.json") if not f.endswith("_extra.json"))
    malls = [json.load(open(f)) for f in files]
    # gabung *_extra.json ke mall yg sepadan nama
    for xf in glob.glob(f"{HARVEST}/*_extra.json"):
        x = json.load(open(xf))
        for m in malls:
            if m["mall"] == x["mall"]:
                m["outlets"] += x["outlets"]
                break
    # tapis: buang bukan-outlet-makanan + dedup nama dlm satu mall
    for m in malls:
        seen, kept = set(), []
        for o in m["outlets"]:
            nm = html.unescape(o["name"])
            k = nm.strip().lower()
            if k in seen or not is_food_outlet(nm):
                continue
            seen.add(k); kept.append(o)
        m["outlets"] = kept
        m["count"] = len(kept)

    # kumpul semua nama unik utk query sekali
    keys = {}
    for m in malls:
        for o in m["outlets"]:
            keys.setdefault(norm_key(o["name"]), html.unescape(o["name"]))
    # TTL: re-query nama baharu ATAU entri lama (> HALAL_TTL_DAYS). Ganti clear-penuh.
    ttl = float(os.environ.get("HALAL_TTL_DAYS", "14")) * 86400
    now = time.time()
    todo = [k for k in keys if k not in cache or (now - cache[k].get("ts", 0)) > ttl]
    print(f"{sum(len(m['outlets']) for m in malls)} outlet, {len(keys)} unik, "
          f"{len(todo)} perlu query (baki {len(keys)-len(todo)} dari cache masih segar)")

    for i, k in enumerate(todo, 1):
        cnt, holder, matched = myehalal_check(keys[k])
        cache[k] = {"count": cnt if isinstance(cnt, int) else 0,
                    "holder": holder, "matched": bool(matched), "ts": now}
        if i % 20 == 0:
            print(f"  {i}/{len(todo)} ...")
            json.dump(cache, open(CACHE_FILE, "w"), ensure_ascii=False)
        time.sleep(0.35)
    json.dump(cache, open(CACHE_FILE, "w"), ensure_ascii=False, indent=1)

    grand = {}
    combined = []
    for m in malls:
        rows = []
        for o in m["outlets"]:
            c = cache[norm_key(o["name"])]
            st = classify(html.unescape(o["name"]), c["count"], c["matched"])
            rows.append({"name": html.unescape(o["name"]), "lot": o.get("lot"),
                         "status": st, "myehalal_matches": c["count"],
                         "cert_holder": c["holder"]})
        summ = {s: sum(r["status"] == s for r in rows)
                for s in ("certified", "review", "uncertified", "non_halal")}
        slug = re.sub(r"[^a-z0-9]+", "_", m["mall"].lower()).strip("_")
        json.dump({"mall": m["mall"], "directory_url": m.get("directory_url"),
                   "count": len(rows), "summary": summ, "outlets": rows},
                  open(f"{OUTDIR}/{slug}.json", "w"), indent=2, ensure_ascii=False)
        grand[m["mall"]] = summ
        combined.append({"mall": m["mall"], "summary": summ})
        print(f"  {m['mall']:32} {summ}")

    json.dump({"note": "status: certified=nama padan holder sijil | review=ada sijil "
                       "tapi nama holder lain, semak manual | uncertified=tiada sijil "
                       "JAKIM (BUKAN haram) | non_halal=keyword khinzir/arak",
               "source": "JAKIM MyeHalal (myehalal.halal.gov.my), kategori PE",
               "malls": combined},
              open("stores_all.json", "w"), indent=2, ensure_ascii=False)
    tot = {s: sum(v[s] for v in grand.values())
           for s in ("certified", "review", "uncertified", "non_halal")}
    print(f"\nJUMLAH {len(malls)} mall: {tot}")


if __name__ == "__main__":
    main()
