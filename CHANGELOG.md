# Changelog — Halal Tracker

Semua perubahan penting pada projek ini direkodkan di sini.

## [Julai 2026]

### Ditambah
- **Sokongan Multi-Mall** 🏬 — paparan dan pengurusan data F&B untuk pelbagai
  pusat membeli-belah dalam satu sistem (bukan lagi satu mall sahaja).
- **Google Sign-In** 🔐 — log masuk menggunakan Google, menggantikan borang
  emel/kata laluan lama; verifikasi `id_token` di sisi pelayan.
- **Penyelarasan Data MyeHALAL** ✅ — status pensijilan halal diselaraskan
  dengan portal rasmi JAKIM MyeHalal (kategori Premis Makanan) untuk semua
  premis tersenarai, dengan cache TTL.
- **Muat Naik Sijil Halal** 📷 — pengguna boleh memuat naik gambar sijil halal
  sesebuah kedai; admin nampak kiraan menunggu semakan pada panel admin untuk
  pengesahan (dengan semakan silang MyeHalal automatik semasa lulus).
- **Paparan Awam** 👀 — pengunjung boleh melihat halaman utama dan ringkasan
  tanpa log masuk; senarai penuh status halal (kabur untuk tetamu) dipaparkan
  selepas log masuk dengan Google.
- **Carian Mall** 🔍 — pemilih mall bertukar menjadi kotak carian; taip nama
  mall untuk cari dengan pantas, senarai penuh tetap tersedia.
- **Cadangan Mall Baharu** 🏙️ — pengguna boleh mencadangkan mall yang tiada
  dalam senarai; admin menyemak dan meluluskan dari panel admin.
- **Penapisan mengikut kategori** 🎯 — kad statistik (Halal / Perlu Semak /
  Tiada Sijil / Non-Halal) boleh diklik untuk menapis jadual mengikut kategori,
  serta dropdown penapis status pada jadual. Tetamu perlu log masuk untuk
  melihat senarai yang ditapis.
- **Segar semula automatik mingguan** 🔄 — cron di VPS re-harvest keluarga mall
  bertitik-akhir stabil (Sunway, Imago, IPC, AEON) dan menyemak semula status
  MyeHalal; mengekalkan senarai terakhir jika sumber gagal.
- **IPC Shopping Centre** ditambah ke direktori dengan handler auto-refresh
  tersendiri.

### Diperbaiki / teknikal
- Semakan MyeHalal guna `curl` (bukan `urllib`) kerana jabat-tangan TLS gagal
  dengan pelayan kerajaan.
- Normalisasi nama carian (buang `'s`, `&`, aksara CJK) supaya jenama seperti
  "McDonald's" dan "A&W" dapat padanan betul.
- Kunci `flock` pada cron untuk elak tindihan larian yang pernah merosakkan cache.
- Cache TTL memendekkan larian mingguan dari ~2 jam ke ~1 minit.
