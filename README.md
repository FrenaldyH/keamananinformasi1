# Secure Storage — Tugas 1 Keamanan Informasi

Aplikasi web sederhana untuk menyimpan **data pribadi, foto KTP, dokumen (PDF/DOC/XLS), dan video**.
Semua data disimpan **terenkripsi dengan AES, DES, dan RC4** (masing-masing satu salinan), memakai
mode non-ECB (AES-256-CBC, DES-CBC; RC4 adalah stream cipher). User harus login dengan
username + password untuk mengambil data yang sudah didekripsi.

> Penjelasan lengkap ada di [notes/PENJELASAN.md](notes/PENJELASAN.md).
> Laporan analisis (waktu & ciphertext) ada di [notes/LAPORAN.md](notes/LAPORAN.md).

## Struktur


| File          | Isi                                                                           |
| --------------- | ------------------------------------------------------------------------------- |
| `app.py`      | Backend Flask: register/login, upload terenkripsi, list, download terdekripsi |
| `ciphers.py`  | Fungsi enkripsi/dekripsi AES, DES, RC4 + penurunan kunci dari password        |
| `lihat_db.py` | Alat demo: menampilkan isi mentah database (bukti data terenkripsi)           |
| `static/`     | Frontend HTML + CSS + JS polos                                                |
| `data.db`     | Database SQLite (dibuat otomatis saat server pertama jalan)                   |

## Menjalankan

Butuh Python 3.10+.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python ciphers.py      # self-test kripto -> "ciphers.py self-check OK"
.venv/bin/python app.py          # server di http://127.0.0.1:5000
```

(Windows: ganti `.venv/bin/` dengan `.venv\Scripts\`.)

## Langkah Demo (± 10 menit)

Siapkan dulu: 1 gambar (jpg/png) sebagai "foto KTP", 1 file PDF/DOCX/XLSX, 1 video MP4 (makin besar,
misal 20–50 MB, makin jelas perbedaan waktunya).

1. **Mulai bersih (opsional).** Hentikan server, hapus `data.db`, jalankan lagi `.venv/bin/python app.py`.
2. **Self-test kripto.** Jalankan `.venv/bin/python ciphers.py` → tunjukkan `self-check OK`
   (uji enkripsi→dekripsi di 3 algoritma, berbagai ukuran data, dan bahwa IV acak menghasilkan ciphertext berbeda).
3. **Register & login.** Buka `http://127.0.0.1:5000`, isi username `demo` + password `rahasia123`,
   klik **Register**, lalu **Login**.
   - Coba login dengan password salah → muncul "Username atau password salah".
4. **Simpan data pribadi.** Isi form *Data Pribadi* (nama, NIK 16 digit, tanggal lahir, alamat, HP, email)
   → **Simpan**. Muncul baris baru jenis `profile` di tabel.
5. **Upload file.** Pilih *Foto KTP* → pilih gambar → **Upload**. Ulangi untuk *Dokumen* dan *Video*.
   - Coba upload file `.exe` sebagai dokumen → ditolak server (validasi ekstensi).
6. **Lihat tabel.** Kolom AES/DES/RC4 menunjukkan ukuran ciphertext & waktu enkripsi tiap algoritma.
   Jelaskan: AES & DES sedikit lebih besar (padding), RC4 sama persis dengan ukuran asli.
7. **Ambil data (dekripsi).** Pilih algoritma di dropdown (aes/des/rc4) → **Lihat**.
   Gambar/video tampil, profil tampil sebagai JSON, dokumen muncul sebagai link download.
   Tunjukkan bahwa hasilnya sama untuk ketiga algoritma.
8. **Lihat ciphertext.** Klik **Ciphertext** → tabel IV/nonce, ukuran, dan 24 byte pertama ciphertext.
   Upload ulang file yang sama → ciphertext-nya beda total (karena IV acak = bukti bukan ECB).
9. **Benchmark.** Klik **Benchmark x10** pada video → aplikasi men-download file 10x per algoritma dan
   menampilkan rata-rata waktu dekripsi + SHA-256 hasil (harus "IDENTIK").
10. **Bukti DB terenkripsi.** Di terminal lain: `.venv/bin/python lihat_db.py` → isi database hanya
    hash password dan byte acak, tidak ada NIK/nama yang terbaca. (Contoh: file JPEG asli selalu
    diawali `FFD8FF`, tapi ciphertext-nya tidak.)
11. **Isolasi antar user.** Buka jendela incognito, register & login user lain → tabelnya kosong;
    data user `demo` tidak bisa diakses.
12. **Logout.** Klik **Logout** → kunci dihapus dari memori server, data tidak bisa diambil lagi sampai login.
