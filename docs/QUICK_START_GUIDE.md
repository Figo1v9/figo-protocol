# 📖 دليل التشغيل السريع والأوامر الجاهزة — FigoX Protocol (FGXP v2)

مستند إرشادي مخصص يحتوي على خطوات التشغيل التفصيلية للأوامر على كلٍّ من خادم الـ VPS (عبر الـ SSH) والجهاز المحلّي (عبر الـ Windows PowerShell).

---

## ⚡ الـ Master Cheat Sheet (أمر سطر واحد لكل VPS جديد)

### 1️⃣ أمر السيرفر على Google Cloud VPS SSH (بعد رفع `fgxp-server-linux`):
```bash
chmod +x fgxp-server-linux && sudo pkill -f fgxp-server ; sudo nohup ./fgxp-server-linux --listen 0.0.0.0:80 --no-tls --psk "my-secure-shared-key-32bytes" > server.log 2>&1 &
```

### 2️⃣ أمر العميل على جهازك المحلّي (Windows PowerShell):
```powershell
.\bin\fgxp-client.exe --server NEW_VPS_IP:80 --psk "my-secure-shared-key-32bytes" --sni "http://digital.gov.eg/" --socks-listen 127.0.0.1:1081
```

---

## 🖥️ القسم الأول: الخطوات على خادم الـ VPS (عبر الـ SSH)

### 1️⃣ الخطوة الأولى: تجهيز وبناء الملف على جهازك ثم رفعه للـ VPS

في نافذة **PowerShell** على جهازك المحلي، قم ببناء النسخة الخاصة بـ Linux:
```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o bin/fgxp-server-linux ./cmd/fgxp-server
```
ثم قم برفع ملف `fgxp-server-linux` من مجلد `bin` إلى خادم الـ VPS (عن طريق زر **Upload File** في متصفح Google Cloud أو عبر برنامج WinSCP / FileZilla).

---

### 2️⃣ الخطوة الثانية: إعطاء تصريح التشغيل للسيرفر في الـ SSH
افتح كونسول الـ SSH على الـ VPS واكتب الأمر التالي:
```bash
chmod +x fgxp-server-linux
```

---

### 3️⃣ الخطوة الثالثة: تشغيل السيرفر في الخلفية بشكل دائم (`nohup`)

اختر أحد النمطين التاليين حسب نوع الهوست المسموح لديك:

#### 🔹 النمط (أ): تشغيل نمط HTTP الصريح على البورت 80 (للهوستات المجانية بدون رصيد `http://`)
استخدم هذا الأمر عندما يكون الهوست المسموح غير مشفر ويعمل على البورت 80 (مثل `http://digital.gov.eg/`):
```bash
sudo nohup ./fgxp-server-linux --listen 0.0.0.0:80 --no-tls --psk "my-secure-shared-key-32bytes" > server.log 2>&1 &
```

#### 🔹 النمط (ب): تشغيل النمط المشفر على البورت 443 (للهوستات المشفرة `https://`)
استخدم هذا الأمر عند التعامل مع هوستات مسموحة تدعم تشفير الـ HTTPS على البورت 443:
```bash
sudo nohup ./fgxp-server-linux --listen 0.0.0.0:443 --psk "my-secure-shared-key-32bytes" > server.log 2>&1 &
```

---

### 4️⃣ الخطوة الرابعة: أوامر فحص ومراقبة وإيقاف السيرفر في الـ SSH

- **للتحقق من أن السيرفر يعمل حالياً في الخلفية:**
  ```bash
  ps aux | grep fgxp-server
  ```

- **لمشاهدة سجلات السيرفر المباشرة (Live Logs):**
  ```bash
  tail -f server.log
  ```

- **لإيقاف السيرفر في أي وقت:**
  ```bash
  sudo pkill -f fgxp-server
  ```

---

## 💻 القسم الثاني: الخطوات على جهازك المحلّي (Windows PowerShell)

### 1️⃣ بناء العميل على جهازك (مرة واحدة)
افتح الـ **PowerShell** في مجلد المشروع واكتب:
```powershell
go build -o bin/fgxp-client.exe ./cmd/fgxp-client
```

---

### 2️⃣ تشغيل العميل حسب حالة الاتصال والشبكة

#### 🔹 الحالة (أ): الاتصال بهوست مجاني عادي `http://` (على البورت 80)
```powershell
.\bin\fgxp-client.exe --server YOUR_VPS_IP:80 --psk "my-secure-shared-key-32bytes" --sni "http://digital.gov.eg/" --socks-listen 127.0.0.1:1081
```

#### 🔹 الحالة (ب): الاتصال بهوست مشفر `https://` (على البورت 443)
```powershell
.\bin\fgxp-client.exe --server YOUR_VPS_IP:443 --psk "my-secure-shared-key-32bytes" --sni "https://artistudio.fun/download?nocache=123" --socks-listen 127.0.0.1:1081
```

#### 🔹 الحالة (جـ): الاتصال المتقدم بتقنية الـ Domain Fronting (`--real-ip`)
استخدم هذه الطريقة لو كنت ترغب بتوجيه الاتصال لـ IP سيرفرك مباشرة مع الحفاظ على الـ SNI النظيف المسموح للشبكة:
```powershell
.\bin\fgxp-client.exe --server "whitelisted-domain.com:443" --real-ip "YOUR_VPS_IP:443" --psk "my-secure-shared-key-32bytes" --sni "https://whitelisted-domain.com/download?nocache=123" --socks-listen 127.0.0.1:1081
```

---

## 🌐 القسم الثالث: ضبط المتصفح للتصفح عبر النفق

بمجرد تشغيل العميل في الـ PowerShell ورؤية الرسالة:
`SOCKS5 Proxy listener started on 127.0.0.1:1081`

1. قم بفتح متصفحك (Google Chrome / Firefox / Edge).
2. ثبّت إضافة البروكسي (مثل **Proxy SwitchyOmega**).
3. اضبط البروكسي كالتالي:
   - **Protocol**: `SOCKS5`
   - **Server / Host**: `127.0.0.1`
   - **Port**: `1081`
4. فعّل البروكسي وابدأ التصفح بأعلى سرعة وأمان!
