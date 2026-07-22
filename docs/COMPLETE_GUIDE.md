# 🚀 FigoX Protocol (FGXP v2) — الدليل الشامل والمستند التشغيلي الأقصى

مرحباً بك في **FigoX Protocol (FGXP)** — البروتوكول الهندسي المتقدم من الجيل التالي المصمم خصيصاً لتخطي كافة طبقات التفتيش العميق للحزم (DPI)، أجهزة جدران الحماية السيادية، ونظم التضييق الشبكي، مع تقديم أعلى معدلات نقل بيانات سرعة واستقراراً.

---

## 🌟 مميزات البروتوكول الفريدة (Key Features)

### 1. استنساخ بصمة المتصفح الحقيقية (uTLS Browser Parity)
- يتغلب على نظام الفحص ببصمة المشفر (JA3 / JA4 Fingerprinting) عن طريق استنساخ حزمة الـ `ClientHello` لمتصفح **Google Chrome** أو **Firefox** أو **Edge** بايت ببايت (`HelloChrome_Auto`).
- حركة مرور البيانات تظهر على خوادم الشبكة كأنها تصفح ويب طبيعي 100%.

### 2. محرك تغليف الـ L7 والروابط الكاملة (Full Transport URL & HTTP Framing)
- يدعم كتابة وتفكيك الروابط المعقدة تلقائياً داخل خيار `--sni`:
  `https://speedtest8.example.com:8080/download?nocache=e67ec7c5-6f5d-4c13-9eb7-ffc67df76bc4&size=25000000`
- يقوم باستخلاص اسم الـ SNI النظيف لطبقة الـ TLS، وفي الوقت نفسه يرسل طلب `GET /download?... HTTP/1.1` كاملاً في طبقة الـ HTTP الأولى لإقناع الفلاتر أنك تتصفح الهوست المسموح بالكامل.

- يقضي تماماً على ثغرة فحص المطابقة المتقاطعة بين الـ IP والـ DNS (IP-to-SNI Mismatch).

### 4. النمط المزدوج لروابط `http://` و `https://` (Dual Plaintext & TLS HTTP Framing)
- يدعم التمييز والتكيف التلقائي مع الروابط:
  - عند استخدام رابط **`http://`** (مثل `http://digital.gov.eg/`): العميل يرسل طلب `GET / HTTP/1.1` صريح بدون TLS أولاً ليمر عبر فلاتر البورت 80 وتخطي الشبكات التي تشترط بروتوكول HTTP الصريح بدون تشفير أولي.
  - عند استخدام رابط **`https://`**: يتم استخدام **uTLS** مع حزمة `ClientHello` المطابقة لمتصفح Chrome للتخطي المشفر عبر البورت 443.

### 4. مقاومة الفحص النشط والتمويه الذكي (Active Probe Resistance & Camouflage)
- يتعرف السيرفر تلقائياً على الماسحات وأجهزة الفحص النشط (Active Probers).
- إذا ورد اتصال غير معتمد أو فحص HTTP مباشر، يقوم السيرفر بتحويل الفاحص تلقائياً إلى سيرفر تمويه محلي (Camouflage Web Server) يرد بصفحة موقع حقيقية (`200 OK` HTML)، مما يمنع اكتشاف وجود سيرفر بروكسي.

### 5. محرك السرعة العالية وعدم تساقط الحزم (Gigabit-Ready & Backpressure Control)
- يعتمد على ذاكرة مؤقتة معاد استخدامها تلقائياً (`sync.Pool`) تمنع استهلاك الـ CPU والـ RAM.
- يحتوي على نافذة تدفق بيانات هائلة **64MB Flow Control Window** تجعل النفق جاهزاً للسرعات العالية (1Gbps+).
- يطبق نظام **Backpressure Flow Control** و **Unread Byte Protection** للعمل بإنتاجية مثبتة تتجاوز **18.84 MB/s** بدون أي تهنيق أو تساقط للحزم.

### 6. التشويه الإحصائي للحزم (CSPRNG Entropy Padding)
- حشو الحزم بأرقام مشفرة عشوائية يرفع نسبة العشوائية (Entropy) لـ **7.9820 من 8.0000**، مما يجعل الحزم غير قابلة للتمييز الإحصائي عن حزم الـ TLS العالمية.

---

## 🛠️ كيفية البناء والتشغيل (Quick Setup & Build)

### 1. بناء الملفات التنفيذية (Build Binaries)
قم بفتح الـ Terminal في مجلد المشروع وتشغيل أمر البناء:
```powershell
go build -o bin/fgxp-server.exe ./cmd/fgxp-server
go build -o bin/fgxp-client.exe ./cmd/fgxp-client
```

---

## 💻 طريقة الاستخدام التشغيلي (Usage Examples)

### أولاً: تشغيل السيرفر على الـ VPS (`fgxp-server`)

افتح نافذة الكونسول على خادم الـ VPS واكتب الأمر التالي:
```powershell
.\bin\fgxp-server.exe --listen 0.0.0.0:8443 --cert cert.pem --key key.pem --psk "my-secure-shared-key-32bytes"
```

---

## 🔒 دليل استخراج وتثبيت شهادات SSL الرسمية (Let's Encrypt Production Guide)

لقفل آخر نقطة ضعف (فحص صحة الشهادة وتطابق الـ DNS 100%)، يوصى باستخراج شهادة SSL رسمية ومجانية من **Let's Encrypt** على خادم الـ VPS الخاص بك كالتالي:

### 1. ربط الـ IP بالدومين الخاص بك (DNS A Record):
- افتح لوحة التحكم لدومينك (Cloudflare أو Namecheap أو GoDaddy).
- أضف سجل `A Record`:
  - **Name**: `subdomain.yourdomain.com`
  - **IPv4 Address**: `YOUR_VPS_IP`

### 2. تثبيت Certbot واستخراج الشهادة على سيرفر الـ Linux/VPS:
```bash
# 1. تحديث النظام وتثبيت certbot
sudo apt update && sudo apt install -y certbot

# 2. استخراج شهادة رسمية وموثوقة لدومينك
sudo certbot certonly --standalone -d subdomain.yourdomain.com --preferred-challenges http
```

بعد نجاح الأمر، ستجد الشهادات الرسمية الموثوقة مسجلة في المسار التالي:
- **مسار الشهادة الكاملة (`cert`)**: `/etc/letsencrypt/live/subdomain.yourdomain.com/fullchain.pem`
- **مسار المفتاح الخاص (`key`)**: `/etc/letsencrypt/live/subdomain.yourdomain.com/privkey.pem`

### 3. تشغيل `fgxp-server` بالشهادة الرسمية:
```bash
./bin/fgxp-server --listen 0.0.0.0:8443 \
  --cert /etc/letsencrypt/live/subdomain.yourdomain.com/fullchain.pem \
  --key /etc/letsencrypt/live/subdomain.yourdomain.com/privkey.pem \
  --psk "my-secure-shared-key-32bytes"
```

---

### ثانياً: تشغيل العميل (`fgxp-client`) حسب حالة الاستخدام

#### 1️⃣ الاستخدام العادي (دومين عادي):
```powershell
.\bin\fgxp-client.exe --server YOUR_VPS_IP:8443 --psk "my-secure-shared-key-32bytes" --sni "example.com" --socks-listen 127.0.0.1:1081
```

#### 2️⃣ الاستخدام المتقدم لـ هوست معقد ورابط كامل (Full Transport URL):
تستخدم هذه الطريقة عند التعامل مع هوست متفلتر يشترط وجود مسار ومعاملات استعلام:
```powershell
.\bin\fgxp-client.exe --server YOUR_VPS_IP:8443 --psk "my-secure-shared-key-32bytes" --sni "https://speedtest8.example.com:8080/download?nocache=e67ec7c5-6f5d-4c13-9eb7-ffc67df76bc4&size=25000000" --socks-listen 127.0.0.1:1081
```

#### 3️⃣ التخطي الأقصى عبر الـ Domain Fronting و الـ CDN (`--real-ip`):
تستخدم هذه الطريقة لتوجيه الاتصال لـ IP الـ VPS أو الـ CDN مع الحفاظ على الـ SNI التمويهي:
```powershell
.\bin\fgxp-client.exe --server "whitelisted-domain.com:443" --real-ip "YOUR_VPS_IP:8443" --psk "my-secure-shared-key-32bytes" --sni "https://whitelisted-domain.com/download?nocache=123" --socks-listen 127.0.0.1:1081
```

---

## 🌐 ضبط المتصفح للتصفح عبر النفق (Browser Proxy Configuration)

بعد تشغيل العميل وظهور رسالة `SOCKS5 Proxy listener started on 127.0.0.1:1081`:

1. افتح إعدادات البروكسي في متصفحك (أو ملحق زي **SwitchyOmega**).
2. اختر **SOCKS5 Proxy**.
3. قم بضبط العنوان على: `127.0.0.1` والمنفذ على `1081`.
4. ابدأ التصفح فوراً، وجميع بياناتك ستنقل مشفرة كلياً عبر النفق!

---

## 📋 دليل خيارات السطر البرمجي (CLI Flags Reference)

### خيارات العميل (`fgxp-client`):

| Parameter | Type | Default | Description |
|---|---|---|---|
| `--server` | string | *مطلوب* | عنوان السيرفر والمنفذ (`host:port`) |
| `--psk` | string | *مطلوب* | مفتاح التشفير المشترك (Must be secure string) |
| `--sni` | string | `""` | اسم النطاق التمويهي أو الرابط الكامل (`https://domain/path?query`) |
| `--real-ip` | string | `""` | [جديد] رقم الـ IP التكتيكي للاتصال المباشر (Domain Fronting) |
| `--transport` | string | `tcp` | نوع النقل: `tcp` (مع uTLS) أو `quic` |
| `--socks-listen` | string | `127.0.0.1:1080` | منفذ الـ SOCKS5 المحلّي لجهازك |
| `--log-level` | string | `info` | مستوى السجلات: `debug`, `info`, `warn`, `error` |

### خيارات السيرفر (`fgxp-server`):

| Parameter | Type | Default | Description |
|---|---|---|---|
| `--listen` | string | `:8443` | عنوان ومنفذ استماع السيرفر |
| `--cert` | string | `""` | مسار شهادة TLS (`cert.pem`) |
| `--key` | string | `""` | مسار المفتاح الخاص لشهادة TLS (`key.pem`) |
| `--no-tls` | bool | `false` | [جديد] إلغاء تشفير TLS للسيرفر للعمل بنمط Plaintext HTTP Framing المباشر على البورت 80 |
| `--psk` | string | *مطلوب* | مفتاح المصادقة والتشفير المشترك |
| `--config` | string | `""` | مسار ملف الإعدادات الكامل (`config.yaml`) |

---

## 🛠️ سجل المشاكل الفنية الشامل والحلول التكتيكية (Troubleshooting & Lessons Learned)

سجل تفصيلي بكل التحديات العنائية والشبكية التي واجهناها أثناء الاختبارات الفعلية وكيف تم حلها وتطوير البروتوكول للقضاء عليها:

### 1️⃣ بطء السرعة وانقطاع الاتصال بعد دقيقة واحدة (High Throughput Slowdown & Stall):
- **الأعراض:** السيرفر والعميل يتصلان بسرعة عالية في البداية، ثم تنخفض السرعة تدريجياً لـ 0KB/s ويلزم إعادة التشغيل `Ctrl+C`.
- **السبب الهندسي:** 
  1. اقتطاع البايتات الجزئية (Partial Read Truncation) في كلاس الـ Stream.
  2. تساقط الحزم الصامت (Silent Frame Dropping) في صف طوابير `QueueFrame` عند الضغط العالي بدون وجود نظام رادع للضغط العكسي (Backpressure).
  3. قفل البورتات الخاملة من قِبل المزود وموجهات الـ NAT لعدم وجود نبضات استمرار.
- **الحل الهندسي المطبق:** 
  - إضافة ذاكرة متبقيات `unread []byte` داخل `Stream.Read`.
  - تطبيق **Backpressure Flow Control** حظر متزامن بدلاً من التخلي الصامت عن الحزم عند امتلاء الـ Buffer.
  - تشغيل محرك **Keep-Alive PING Ticker** يرسل حزمة نبض كل 15 ثانية لإبقاء النفق مفتوحاً بشكل دائم.

---

### 2️⃣ عدم مطابقة رقم الـ IP لاسم الـ SNI النظيف (IP-to-SNI Mismatch):
- **الأعراض:** الفلاتر السيادية المتقدمة تقارن الـ Destination IP بسجلات الـ DNS الخاصة بالـ SNI المكتوب وترفض الاتصال.
- **الحل الهندسي المطبق:**
  - تطوير خيار **`--real-ip`** للعميل لتوجيه الاتصال لـ IP الـ VPS أو الـ CDN مباشرة مع إرسال الـ SNI التمويهي في حزمة التشفير بشكل منفصل وتام.

---

### 3️⃣ طلب المزود لرابط كامل مسار وبورت في الـ Host Header (Full Transport URL):
- **الأعراض:** بعض شبكات الموبايل بدون رصيد ترغم الاتصال على التواجد على مسار محدد وبورت خاص لتجاوز البوابة.
- **الحل الهندسي المطبق:**
  - إضافة محرك **`ParseTransportURL`** ومحرك الـ **L7 HTTP Framing** ليفكك الرابط ويرسل طلب الـ GET كاملاً بالمسار والبورت والمعاملات قبل فتح مجاري البيانات.

---

### 4️⃣ رفض اتصالات الـ HTTP الصريحة على البورت 80 (`http://` vs `https://` Mismatch):
- **الأعراض:** عند محاولة الاتصال بهوست مجاني يعمل ببروتوكول HTTP الصريح على البورت 80 (مثل `http://digital.gov.eg/`)، شبكة الموبايل ترفض حزم الـ TLS المباشرة وتغلق الاتصال `wsarecv`.
- **الحل الهندسي المطبق:**
  - تطوير النمط المزدوج **Dual HTTP Framing Engine**: عند كشف رابط `http://` غير مشفر، العميل والسيرفر ينتقلان تلقائياً لنمط **Plaintext TCP + HTTP Framing** ويرسلان طلب `GET / HTTP/1.1` صريح كأول حزمة على الشبكة ليمر من فلاتر المزود على البورت 80 بنجاح.
  - إضافة علم **`--no-tls`** للسيرفر لتشغيل البورت 80 بدون شهادات TLS.

---

### 5️⃣ إغلاق السيرفر عند قطع الاتصال أو فصل الـ USB Tethering (`SIGHUP` Signal):
- **الأعراض:** السيرفر يتوقف فوراً عن العمل أول ما تقفل نافذة الـ SSH أو تتفصل داتا الموبايل.
- **الحل التشغيلي المطبق:**
  - تشغيل السيرفر في خلفية الـ Linux كـ Daemon باستخدام `nohup ... &`:
    `sudo nohup ./fgxp-server-linux --listen 0.0.0.0:80 --no-tls --psk "secret" > server.log 2>&1 &`

---
*تم تحديث هذا الدليل لبروتوكول FigoX Protocol (FGXP v2).*
