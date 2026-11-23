# Security hardening (critical scope)

## Perubahan utama
- Startup ditolak jika `UPLOAD_TOKEN` kurang dari 32 byte.
- Rate limit endpoint upload (default 30 request/menit per IP).
- Pemeriksaan signature dasar untuk PDF, Office, gambar, CSV, dan TXT.
- Upload konkuren dibatasi (default 8); request tambahan mendapat HTTP 503.
- Pemeriksaan ruang kosong NAS sebelum menerima upload; default menyisakan 1 GiB.
- Request timeout dan connection timeout diaktifkan.
- Folder hanya dari query string atau header, maksimal 4 segmen dan 32 karakter per segmen.
- Health endpoint tidak mengembalikan path penyimpanan.
- Log Pino terstruktur; token tidak dicatat.
- File ditulis ke `.part`, lalu dipindahkan dengan rename setelah pipeline berhasil.
- File dibuat dengan mode 0640 dan direktori dengan mode 0750 (tetap dipengaruhi permission/ACL NAS dan umask).

## Instalasi

```bash
npm install
cp .env.example .env
openssl rand -base64 48
```

Masukkan hasil token ke `UPLOAD_TOKEN` di `.env`. Pastikan user service Node.js memiliki hak tulis pada mount NAS.

```bash
npm start
```

## Format request

Folder dikirim melalui query string:

```bash
curl -X POST 'http://127.0.0.1:3000/upload?folder=classroom/2026' \
  -H 'X-Upload-Token: TOKEN_RAHASIA' \
  -F 'file=@dokumen.pdf'
```

Atau melalui header `X-Upload-Folder`. Jangan kirim field multipart bernama `folder` lagi.

## Catatan validasi file
- Signature ZIP pada `.docx`, `.xlsx`, dan `.pptx` hanya membuktikan bahwa file diawali signature ZIP. Ini belum memvalidasi struktur internal Office Open XML atau memastikan file aman.
- CSV/TXT diperiksa sebagai teks UTF-8 yang tidak tampak seperti data biner. Pemeriksaan ini tidak mendeteksi formula injection pada CSV.
- Magic bytes bukan antivirus. Untuk lingkungan produksi yang menerima file dari pihak tidak tepercaya, tambahkan pemindaian ClamAV sebelum file dipindahkan ke nama final/dianggap tersedia.
- `.doc`, `.xls`, dan `.ppt` format lama tetap diizinkan untuk kompatibilitas, tetapi sebaiknya dihapus dari allowlist bila tidak diperlukan.

## Catatan NAS dan reverse proxy
- `UPLOAD_DIR` harus menunjuk ke mount SMB/NFS yang sudah tersedia sebelum service dimulai.
- Pemeriksaan `statfs` adalah pemeriksaan ruang kosong sebelum upload, bukan kuota transaksional; beberapa upload paralel masih dapat berlomba memakai ruang yang sama.
- Jangan aktifkan `trustProxy` secara umum tanpa konfigurasi proxy tepercaya. Jika service berada di belakang Cloudflare Tunnel/reverse proxy, atur kepercayaan proxy dan rate-limit key berdasarkan alamat klien yang benar setelah topologi deployment dipastikan.
- `rename` bersifat atomik hanya jika file sementara dan tujuan berada pada filesystem/mount yang sama.
- Timeout 120 detik perlu diuji dengan ukuran 20 MB dan kecepatan uplink terendah yang realistis.
