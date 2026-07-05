# Halal Tracker

Sistem yang mengumpul senarai kedai F&B dari direktori rasmi pusat membeli-belah
di Malaysia, menyemak status pensijilan halal setiap outlet terhadap portal rasmi
**JAKIM MyeHalal**, dan memaparkannya sebagai papan pemuka web berbilang-mall.

> **Prinsip:** *Tiada sijil ≠ haram.* Ketiadaan rekod sijil dikelaskan sebagai
> "Tiada Sijil" (`uncertified`), bukan haram.

Dokumentasi teknikal penuh: [`Dokumentasi_Halal_Tracker.docx`](Dokumentasi_Halal_Tracker.docx)

## Aliran proses

```
malls.json  →  harvest/<mall>.json  →  central_check.py  →  stores/<mall>.json  →  data.json  →  app.py (papan pemuka)
                  (handler per-mall)     (tapis, dedup,        (status 4-peringkat)
                                          semak MyeHalal)
```

| Peringkat | Maksud |
|-----------|--------|
| `certified` | Ada sijil halal JAKIM yang sah (nama pemegang sepadan) |
| `review` | Ada padanan sijil tetapi nama pemegang berbeza — semak manual |
| `uncertified` | Tiada rekod sijil JAKIM (BUKAN bermaksud haram) |
| `non_halal` | Jelas non-halal (kata kunci babi/arak) |

## Fail utama

| Fail | Peranan |
|------|---------|
| `malls.json` | Senarai mall + status directory |
| `halal_pilot.py` | Enjin semakan MyeHalal (`myehalal_check`, `classify`) |
| `central_check.py` | Tapis, dedup, cache TTL, hasilkan `stores/*.json` |
| `refresh.py` | Segar semula automatik (re-harvest + re-check) |
| `senangwei_local/app.py` | Aplikasi Flask: papan pemuka, Google Sign-In, muat naik sijil, panel admin |

## Persediaan

```bash
python3 -m venv venv && source venv/bin/activate
pip install flask
cp .env.example .env      # isi GOOGLE_CLIENT_ID, ADMIN_EMAIL
# set env vars, kemudian:
python senangwei_local/app.py
```

## Nota

- Status halal dari **JAKIM MyeHalal** (`myehalal.halal.gov.my`), kategori Premis Makanan (PE).
- Skop **F&B sahaja** — pasar raya, runcit, pawagam, farmasi, kedai buku dikecualikan.
- `users.db`, `.env`, cache dan folder muat naik **tidak** disimpan dalam repo (lihat `.gitignore`).
