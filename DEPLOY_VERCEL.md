# Deploy ke Vercel - Panduan Lengkap

Ikuti langkah-langkah di bawah untuk deploy aplikasi ke Vercel tanpa perlu test lokal.

## Prasyarat
- GitHub account (untuk push repo)
- Vercel account (login via GitHub)
- MongoDB Atlas account (untuk database persistence) — **WAJIB untuk produksi**

## Langkah 1: Siapkan Database (MongoDB Atlas)

1. Buka https://www.mongodb.com/cloud/atlas
2. Login atau buat akun baru
3. Buat cluster baru (free tier tersedia):
   - Pilih "Build a Cluster"
   - Pilih "Free" tier
   - Pilih region terdekat
   - Tunggu cluster selesai dibuat
4. Buat database user:
   - Di sidebar, klik "Database Access"
   - Klik "Add New Database User"
   - Username: `admin` (atau pilih nama lain)
   - Password: buat password kuat
   - Klik "Create User"
5. Allowlist IP:
   - Di sidebar, klik "Network Access"
   - Klik "Add IP Address"
   - Pilih "Allow access from anywhere" (untuk simplicity, atau batasi IP Vercel jika perlu)
   - Klik "Confirm"
6. Dapatkan connection string:
   - Di halaman cluster, klik "Connect"
   - Pilih "Connect your application"
   - Pilih "Python 3.6 or later"
   - Copy connection string (misal: `mongodb+srv://admin:PASSWORD@cluster0.xxxxx.mongodb.net/mydb?retryWrites=true&w=majority`)
   - **Simpan connection string ini — Anda akan butuh di Vercel**

## Langkah 2: Push Repo ke GitHub

Di terminal PowerShell, dari folder project:

```powershell
git init
git add .
git commit -m "Initial commit: Roblox Cookie Checker with Flask and Vercel config"
git branch -M main
git remote add origin https://github.com/USERNAME/roblox-cookie-checker.git
git push -u origin main
```

Ganti `USERNAME` dengan username GitHub Anda. Jika belum membuat repo di GitHub, buat dulu di https://github.com/new.

## Langkah 3: Import ke Vercel & Deploy

1. Buka https://vercel.com/dashboard
2. Klik "Add New..." → "Project"
3. Klik "Import Git Repository"
4. Pilih repo `roblox-cookie-checker` dari list
5. Klik "Import"
6. Di halaman konfigurasi project:
   - **Root Directory**: biarkan kosong (default)
   - **Framework Preset**: biarkan "Other" atau terdeteksi otomatis
   - Klik "Environment Variables" dan tambahkan:

   | Key | Value |
   |-----|-------|
   | `MONGODB_URI` | Paste connection string dari MongoDB Atlas (ganti PASSWORD dengan password Anda) |
   | `DB_NAME` | `robin_cookie_checker` (atau nama lain sesuka Anda) |
   | `SECRET_KEY` | Buat nilai random kuat, misal: `your-super-secret-key-12345` |
   | `ADMIN_PASSWORD` | Password admin yang Anda ingin pakai, misal: `StrongAdminPass123!` |

   Contoh `MONGODB_URI`:
   ```
   mongodb+srv://admin:MySecurePassword123@cluster0.abc123.mongodb.net/robin_cookie_checker?retryWrites=true&w=majority
   ```

7. Klik "Deploy"
8. Tunggu hingga build selesai (2-5 menit)

## Langkah 4: Verifikasi Deployment

1. Setelah deploy selesai, Anda akan diberi URL Vercel (misal: `https://roblox-cookie-checker.vercel.app`)
2. Tes halaman utama:
   ```
   https://roblox-cookie-checker.vercel.app/index.html
   ```
3. Tes login admin:
   - Buka halaman utama, klik Login
   - Username: `admin`
   - Password: (gunakan password yang Anda set di env var `ADMIN_PASSWORD`)
4. Tes API endpoint:
   ```
   GET https://roblox-cookie-checker.vercel.app/api/check
   ```
   Harusnya return JSON dengan status checker.

## Troubleshooting

### Build gagal
- Buka "Deployments" di Vercel, klik deploy yang error, lihat "Build Logs"
- Cek apakah `requirements.txt` lengkap
- Cek apakah `vercel.json` valid JSON

### Login tidak berfungsi / error 500
- Buka "Function Logs" di Vercel dashboard
- Cek apakah `MONGODB_URI` benar (test connection string di MongoDB Atlas)
- Pastikan database user sudah dibuat dan IP allowlisted

### Cookies tidak tersimpan / hilang setelah restart
- Ini normal di Vercel (ephemeral filesystem)
- Pastikan gunakan MongoDB (`MONGODB_URI` valid)
- Data akan disimpan di MongoDB, bukan file lokal

## Environment Variables Referensi

- `MONGODB_URI` — String koneksi MongoDB (format: `mongodb+srv://user:pass@cluster.xxx.mongodb.net/dbname?...`)
- `DB_NAME` — Nama database di MongoDB (default: `robin_cookie_checker`)
- `SECRET_KEY` — Kunci rahasia untuk signing JWT token (ganti dengan nilai random kuat)
- `ADMIN_PASSWORD` — Password login admin (ganti dengan password kuat)

## Setelah Deploy

- Halaman login: `https://your-domain.vercel.app/login.html`
- Halaman admin: `https://your-domain.vercel.app/admin.html` (login dulu)
- API checker: `https://your-domain.vercel.app/api/check`

Selamat — aplikasi Anda sekarang live di Vercel! 🎉
