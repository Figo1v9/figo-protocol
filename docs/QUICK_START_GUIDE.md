# 📖 دليل التشغيل السريع والأوامر الجاهزة — FigoX Protocol (FGXP v2)

مستند إرشادي مخصص يحتوي على خطوات التثبيت التلقائي بسطر واحد على خادم Ubuntu/Debian Linux وأوامر التشغيل على كلٍّ من الـ VPS والجهاز المحلّي (Windows PowerShell).

---

## 🚀 التثبيت التلقائي الكامل بسطر واحد على Ubuntu / Debian (`systemd`)

بدل البناء والرفع اليدوي، شغّل الأمر التالي مباشرةً داخل الـ VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash
```

**أمثلة سريعة لأهم الأوضاع:**
- **بـ IP مباشر + SNI تمويه (`443`):**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash -s -- --sni www.cloudflare.com
  ```
- **بدومين + Let's Encrypt TLS تلقائي (`443`):**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash -s -- --domain vpn.yourdomain.com
  ```
- **بنمط CDN WebSocket (`--mode ws`) للربط عبر Cloudflare CDN أو Imperva CDN:**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash -s -- --mode ws --domain vpn.yourdomain.com
  ```
- **بنمط `--no-tls` على بورت `80` (Cloudflare Worker / HTTP Inject):**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash -s -- --no-tls --sni www.cloudflare.com
  ```

---

## ⚡ الـ Master Cheat Sheet (النشر اليدوي لـ VPS جاهز)

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
يُرسل ترويسة HTTP `Host` نظيفة (مثلاً `http://safaricom.com` أو `http://digital.gov.eg/`):
```powershell
.\bin\fgxp-client.exe --server YOUR_VPS_IP:80 --psk "my-secure-shared-key-32bytes" --sni "http://safaricom.com" --socks-listen 127.0.0.1:1081
```
*(يمكن أيضاً استخدام `--inject` مع بروكسي الشبكة عبر `--proxy 10.x.x.x:8080 --inject safaricom.com --inject-method front` أو `connect`).*

#### 🔹 الحالة (ب): الاتصال عبر CDN WebSocket (`ws` / `wss`) خلف Cloudflare أو Imperva CDN
شغّل السيرفر بالسكربت التلقائي بوضع `--mode ws` (أو مرّر `--ws-path /ws-secret --behind-cdn` لـ `fgxp-server`) ثم اتصل من العميل هكذا:
```powershell
# اتصال مباشر أو عبر دومينك على Cloudflare / Imperva CDN
.\bin\fgxp-client.exe --ws "wss://YOUR-CDN-DOMAIN/ws-secret" --psk "my-secure-shared-key-32bytes" --sni "safaricom.com" --host "YOUR-CDN-DOMAIN" --socks-listen 127.0.0.1:1081

# أو تحديد IP حافة الـ CDN يدوياً (مثل Cloudflare Worker أو Edge IP)
.\bin\fgxp-client.exe --ws "wss://YOUR-CDN-DOMAIN/ws-secret" --real-ip "104.16.132.229:443" --psk "my-secure-shared-key-32bytes" --host "YOUR-CDN-DOMAIN" --sni "safaricom.com" --socks-listen 127.0.0.1:1081
```
> **تنبيه صريح بخصوص `http://safaricom.com` وشبكات Imperva:**
> دومين `safaricom.com` يعمل على شبكة Imperva (`AS19551`). إذا كانت شبكة الموبايل عندك تسمح فقط بـ IP حافة Imperva وترفض الـ VPS المباشر:
> 1. لا يمكن لأي كود داخل السيرفر انتحال IP شبكة Imperva على الإنترنت العام.
> 2. لو الفحص يعتمد على ترويسة `Host` أو `SNI` فقط: استخدم `--no-tls` + `--sni "http://safaricom.com"` أو `--ws` مع `--sni "safaricom.com"`.
> 3. لو الفحص يحظر أي IP خارج CDN: اربط دومينك على Cloudflare (أو Worker مجاني من `configs/cloudflare_worker_relay.js`) أو على Imperva إذا كان لديك حساب موثق عليه.

#### 🔹 الحالة (جـ): الاتصال بهوست مشفر `https://` (على البورت 443)
```powershell
.\bin\fgxp-client.exe --server YOUR_VPS_IP:443 --psk "my-secure-shared-key-32bytes" --sni "https://artistudio.fun/download?nocache=123" --socks-listen 127.0.0.1:1081
```

#### 🔹 الحالة (د): الاتصال المتقدم بتقنية الـ Domain Fronting (`--real-ip`)
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
