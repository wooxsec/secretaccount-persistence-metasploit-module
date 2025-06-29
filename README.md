
# Modul Metasploit: secretaccount-persistence

Modul ini merupakan bagian dari *Post Exploitation* di Metasploit Framework.

Modul ini berisi berbagai teknik persistensi pasca-eksploitasi yang dapat memberikan akses kuat dan tetap tersembunyi di sistem target.

![Tangkapan Layar](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/1.png)

---

## Apa yang dilakukan oleh modul ini?

Pertama, modul akan membuat akun pengguna baru dengan username dan password:

```
Username: secret  
Password: P@ssw0rd123
```

Akun ini dimasukkan ke dalam grup **Administrator**, kemudian **disembunyikan dari menu login** dengan memodifikasi registry Windows.

Meskipun tersembunyi, akun ini masih dapat terlihat melalui "Other Users", sehingga agak tersembunyi namun tetap aktif.

![Tangkapan Layar](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/2.png)

---

## Bypass Windows Defender

Payload diunggah menggunakan arsitektur default dari `msfvenom`, namun **tidak terdeteksi oleh Windows Defender**.

Mengapa? Karena modul ini menghapus semua signature malware dari Windows Defender, sehingga operasi selanjutnya tidak memicu alarm Defender.

![Tangkapan Layar](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/3.png)

---

## Eskalasi Hak Akses

Dengan hak akses terbatas, kita masih bisa membuat **service dengan hak Local System**, dan membangun **rantai backdoor**.

![Tangkapan Layar](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/4.png)

---

## Akses SMB Tanpa Bypass UAC

Tanpa harus melakukan bypass UAC, kita sudah bisa membaca folder Administrator yang dibagikan (shared), dan login ke sistem melalui SMB menggunakan tools seperti:

- `psexec`
- `smbexec`
- `wmiexec`

![Tangkapan Layar](https://github.com/wooxsec/secretaccount-persistence-metasploit-module/blob/main/5.png)

---

## Instalasi

```bash
git clone https://github.com/wooxsec/secretaccount-persistence-metasploit-module
cd secretaccount-persistence-metasploit-module
sudo mv persistence_nighmares.rb /usr/share/metasploit-framework/exploits/windows/local/
```

---

## Menjalankan Modul

Buka terminal dan jalankan Metasploit:

```bash
msfconsole
```

Kemudian muat ulang semua modul agar modul ini terdeteksi:

```bash
reload_all
```

---

💀 Modul ini hanya untuk **tujuan edukasi & pengujian keamanan legal**. Jangan gunakan untuk aktivitas ilegal.
