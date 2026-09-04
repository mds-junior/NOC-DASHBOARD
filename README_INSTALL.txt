LIBRENMS BANDWIDTH V51 - AUTO SETUP

Tidak perlu import SQL.
1. Extract ZIP ke folder web dashboard.
2. Pastikan folder writable oleh web server saat setup.
3. Buka install.php lewat browser.
4. Isi akun MySQL Admin, info database baru, dan Admin dashboard pertama.
5. Klik Create Database & Start Dashboard.
6. Login, lalu klik Users untuk membuat akun Viewer.

Setup otomatis membuat database, user database aplikasi, tabel dashboard_users,
akun Admin pertama, auth_config.php, dan .dashboard_installed.
Password MySQL Admin hanya dipakai saat setup dan tidak disimpan.
Data dashboard_ports.json dan dashboard_profiles.json existing sudah disertakan.
