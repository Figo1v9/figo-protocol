# FigoX Protocol (FGXP)

[![Go Reference](https://pkg.go.dev/badge/github.com/figox/figox-protocol.svg)](https://pkg.go.dev/github.com/figox/figox-protocol)
[![Go Report Card](https://goreportcard.com/badge/github.com/figox/figox-protocol)](https://goreportcard.com/report/github.com/figox/figox-protocol)

**FigoX Protocol (FGXP)** is a premium, next-generation stealth transport protocol built from scratch in Go. It is designed to bypass state-of-the-art Deep Packet Inspection (DPI) firewalls by embedding multiplexed data streams within standard TLS 1.3 or HTTP/3 (QUIC) connections, making FGXP traffic look completely identical to normal web browsing (HTTPS).

- **Full Transport URL & L7 HTTP Framing:** Automatically parses full URLs (`https://host:port/path?query`) into clean TLS SNI and L7 HTTP GET request lines to bypass strict host filtering.
- **Domain Fronting & RealIP Override:** Dial target VPS/CDN IPs directly with `--real-ip` while keeping whitelisted SNI camouflage.
- **uTLS Browser Parity:** Employs uTLS to mirror Google Chrome / Firefox TLS ClientHello fingerprints byte-for-byte (JA3/JA4 evasion).
- **Dual-Transport Evasion:** Fully supports standard TCP + TLS 1.3 tunnels and HTTP/3-mimicked QUIC streams.
- **Active Probe Resistance:** Timing-safe first-byte inspection handles unauthenticated active probes by silently routing them to a camouflage fallback server (Static web page or Reverse Proxy to a legitimate site) acting exactly like Nginx.
- **High Performance & Zero Data Loss:** Stream multiplexing with backpressure flow control, 64MB flow control windows, unread byte buffering, and zero-copy buffer pooling (`sync.Pool`) for gigabit-speed throughput (18.84+ MB/s).

📖 **Documentation & Deployment Guides:**
- ⚡ **[Quick Start Deployment Guide (PowerShell & SSH)](file:///d:/lab/figox-protocol/docs/QUICK_START_GUIDE.md)**
- 📘 **[Complete Technical Architecture & Troubleshooting Guide](file:///d:/lab/figox-protocol/docs/COMPLETE_GUIDE.md)**

---

## Protocol Architecture

FGXP is constructed with a 5-layer decoupled architecture:

```
┌─────────────────────────────────────────────────┐
│  Layer 5: Application Interface (SDK/API)       │
├─────────────────────────────────────────────────┤
│  Layer 4: Stream Multiplexing & Flow Control    │
├─────────────────────────────────────────────────┤
│  Layer 3: Framing & Stealth Obfuscation         │
├─────────────────────────────────────────────────┤
│  Layer 2: Session & Authentication              │
├─────────────────────────────────────────────────┤
│  Layer 1: Transport (TCP+TLS 1.3 / QUIC)        │
└─────────────────────────────────────────────────┘
```

For more detailed technical specifications, state machines, and threat models, please refer to [FGXP-RFC-0001](file:///d:/lab/figox-protocol/docs/FGXP-RFC-0001.md).

---

## Project Structure

```
d:\lab\figox-protocol\
├── cmd/
│   ├── fgxp-server/     # FGXP Server Entrypoint
│   ├── fgxp-client/     # FGXP Client CLI Tool
│   └── fgxp-bench/      # Benchmark Suite
├── pkg/
│   ├── protocol/        # Frame structures, codecs, constants, error codes
│   ├── transport/       # TCP+TLS and QUIC connection wrappers
│   ├── auth/            # PSK Challenge-Response authentication engine
│   ├── session/         # Session state machine, lifecycle management
│   ├── stealth/         # Traffic shaping, padding, timing jitter, active probe resistance
│   ├── stream/          # Priority scheduling (WFQ) Mux and stream implementations
│   ├── congestion/      # Congestion control (CUBIC interface)
│   ├── compress/        # LZ4 and Zstd compression engines
│   ├── config/          # Configuration management, YAML loaders
│   └── observability/   # Metrics tracking, structured logging, health checks
├── test/
│   └── integration/     # End-to-end integration and camouflage tests
├── configs/             # YAML configuration templates
└── Makefile             # Make automation recipes
```

---

## Quick Start

### 1. Build Binaries
Build the server, client, and benchmark executables using `make`:
```bash
make build
```
Binaries will be placed inside the `bin/` directory.

### 2. Configure and Run Server
Copy the server configuration template and run it:
```bash
# Run server directly with a pre-shared key
./bin/fgxp-server --listen :8443 --cert cert.pem --key key.pem --psk "my-secure-psk"
```

### 3. Run Client
Run the client pointing to the server:
```bash
./bin/fgxp-client --server 127.0.0.1:8443 --psk "my-secure-psk" --sni "localhost"
```

---

## Testing & Verification

Run the entire suite of unit and integration tests:
```bash
# Formats code, vets structure, runs unit and integration tests
make
```

### Integration Tests Execution
```bash
go test ./test/integration/... -v
```

---

## Docker Support

Build and run FGXP containers using Docker Compose:
```bash
# Build the Docker image
make docker-build

# Spin up server and client services
docker-compose up -d
```

---

## License

This project is licensed under the MIT License.

---

## دليل التشغيل والتجربة بالتفصيل (Arabic Guide)

هذا الدليل يوضح خطوات بناء وتشغيل النفق، سواء بالتثبيت التلقائي الكامل بسطر واحد على خادم Ubuntu/Debian أو بالنشر اليدوي.

### أولاً: التثبيت التلقائي بسطر واحد على أوبونتو / ديبيان (One-Command Ubuntu Installer)

على أي خادم Ubuntu أو Debian جديد، شغّل هذا الأمر مرة واحدة فقط — هيقوم تلقائياً بتثبيت الاعتماديات وGo `1.26.5`، بناء المشروع، توليد الشهادات وPSK عشوائي، ضبط BBR وجدار الحماية UFW، وتشغيل الخدمة عبر `systemd`:

```bash
curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash
```

**أوضاع التثبيت مع SNI:**

1. **باستخدام IP مباشر + SNI تمويه (بورت `443` — بدون دومين):**
   ```bash
   curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash -s -- --sni www.cloudflare.com
   ```
2. **باستخدام دومين خاص + شهادة Let's Encrypt تلقائية (أقوى تخفّي):**
   *(تأكد أولاً إن سجل DNS من نوع `A` للدومين بيشير لـ IP السيرفر، وإن بورت `80` و `443` مفتوحين في Cloud Firewall)*
   ```bash
   curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash -s -- --domain vpn.yourdomain.com --email you@example.com
   ```
3. **بدون TLS (`--no-tls` على بورت `80`) لربط Cloudflare Worker Relay أو HTTP Injection:**
   ```bash
   curl -fsSL https://raw.githubusercontent.com/Figo1v9/figo-protocol/main/deploy/install-ubuntu.sh | sudo bash -s -- --no-tls --sni www.cloudflare.com
   ```

بعد انتهاء التثبيت هتلاقي أمر العميل الجاهز على الشاشة ومحفوظ في `/etc/fgxp/client-info.txt`. ولأغراض الإنتاج، غيّر الشهادات التجريبية الافتراضية في الجذر (`cert.pem` / `key.pem`) دائماً ولا تشارك الـ PSK علناً.

### ثانياً: النشر والتشغيل الحقيقي (Manual GCP Cloud Deployment)

لتشغيل البروكسي وتغيير الـ IP الخاص بك بالكامل للعبور من جدران الحماية، اتبع هذه الخطوات بعد حجز خادم VPS على **Google Cloud Platform (GCP)**:

#### 1. بناء نسخة الخادم للينكس (Linux Build)
على جهاز الويندوز الخاص بك، قم بتشغيل الأمر التالي لبناء ملف تنفيذي متوافق مع نظام Linux الخاص بالـ VPS:
```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o bin/fgxp-server-linux ./cmd/fgxp-server
```

#### 2. رفع الملفات وتشغيل السيرفر بشكل مستمر على الـ VPS
1. افتح شاشة الـ **SSH** الخاصة بالخادم من متصفحك في Google Cloud Console.
2. من أيقونة **الترس (Settings)** بأعلى اليمين، اختر **`Upload File`** وقم برفع الملفات التالية:
   - `bin/fgxp-server-linux`
   - `cert.pem`
   - `key.pem`
3. في شاشة الـ SSH السوداء بالمتصفح، قم بتشغيل الأمر التالي لتشغيل الخادم في الخلفية (Background process) لضمان استمراره حتى بعد إغلاق المتصفح أو فصل الإنترنت:
   ```bash
   chmod +x fgxp-server-linux
   sudo nohup ./fgxp-server-linux --listen :443 --cert cert.pem --key key.pem --psk "my-secure-shared-key-32bytes" > fgxp.log 2>&1 &
   ```
   *(ستحفظ السجلات وصادر الأخطاء تلقائياً في ملف `fgxp.log` لمراجعتها).*

#### 3. ربط جهازك المحلي (Windows) بالـ VPS
على جهاز الكمبيوتر الخاص بك، افتح الـ PowerShell وشغل العميل ليتصل بالـ IP الخارجي للـ VPS الخاص بجوجل كلاود (مثلاً: `34.91.38.34`) على المنفذ `1083`:
```powershell
.\bin\fgxp-client.exe --server <IP_الخارجي_للخادم>:443 --psk "my-secure-shared-key-32bytes" --sni "www.eand.com.eg" --socks-listen 127.0.0.1:1083
```

#### 4. ضبط متصفح جوجل كروم (Google Chrome Setup)
لكي يتصفح متصفح Chrome عبر النفق المشفر دون المساس بإعدادات الويندوز العامة:
1. قم بتثبيت إضافة **`Proxy SwitchyOmega`** من متجر كروم.
2. افتح إعدادات الإضافة وقم بتعديل ملف التعريف الافتراضي `proxy`:
   - اختر البروتوكول: **`SOCKS5`**.
   - الخادم (Server): **`127.0.0.1`**.
   - المنفذ (Port): **`1083`**.
   - اضغط على **`Apply changes`** لحفظ الإعدادات.
3. اضغط على أيقونة الإضافة في شريط كروم العلوي واختر **`proxy`** لتفعيل النفق.

#### 5. التحقق من نجاح التجاوز وتغيير الـ IP
افتح الـ Terminal وجرب الفحص لمعاينة الـ IP الجديد التابع لجوجل كلاود:
```powershell
curl.exe -s -x socks5h://127.0.0.1:1083 http://httpbin.org/ip
```
ستظهر النتيجة كالتالي مؤكدة خروجك من خادم جوجل في هولندا:
```json
{
  "origin": "<IP_الخارجي_للـVPS>"
}
```

---

### ثالثاً: دليل حل المشاكل الشائعة (Troubleshooting Guide)

#### 1. خطأ حجز المنفذ محلياً (`bind: Only one usage of each socket address is normally permitted`)
* **السبب:** هذا يعني أن منفذ البروكسي (`1083` أو `1082`) لا يزال محجوزاً من قبل عملية عميل قديمة تعمل في الخلفية.
* **الحل:**
  قم بتغيير المنفذ في أمر تشغيل العميل إلى منفذ بديل (مثل `1084` أو `1085`) أو قم بإنهاء العملية القديمة من الـ PowerShell عبر:
  ```powershell
  Stop-Process -Name fgxp-client -Force
  ```

#### 2. انقطاع الاتصال عند التبديل لإنترنت الهاتف (`aborted by the software in your host machine`)
* **السبب:** يؤدي فصل كابل الـ USB أو تبديل كارت الشبكة إلى إغلاق اتصالات الـ TCP المفتوحة في الويندوز تلقائياً.
* **الحل:**
  1. تأكد من تفعيل **USB Tethering** في هاتفك مجدداً بعد توصيل الكابل.
  2. انتظر 5 ثوانٍ لاستقرار شبكة الهاتف على الكمبيوتر.
  3. أعد تشغيل أمر عميل الـ `fgxp-client` مجدداً وسيتصل بالسيرفر المستقر دون مشاكل.

#### 3. إغلاق وتوقف السيرفر عند فصل إنترنت الكمبيوتر
* **السبب:** تشغيل السيرفر بأمر مباشر (`sudo ./fgxp-server-linux`) يربطه بمتصفح الـ SSH، وعند فصل الإنترنت يُغلق المتصفح وتقتل العملية.
* **الحل:** استخدم دائماً أداة **`nohup`** (الموضحة في خطوة التشغيل على الـ VPS) لتشغيل الخادم كعملية مستقلة تماماً في الخلفية.

#### 4. توقف حساب Google Cloud المجاني (Expired Trial)
* **السبب:** انتهاء رصيد الـ 300 دولار التجريبي أو انتهاء فترة الـ 90 يوماً.
* **الحل:**
  1. قم بإنشاء حساب Google Cloud جديد ببريد Gmail آخر.
  2. أنشئ مشروعاً جديداً وقم ببناء الـ VM instance مجدداً (بالمواصفات المجانية Always Free: `e2-micro` في منطقة `us-central1`).
  3. انسخ الـ IP الخارجي الجديد وقم بتعديل أمر تشغيل العميل بجهازك للاتصال بالـ IP الجديد.




Machine configuration:
Series: اختر E2.
Machine type: اختر e2-micro (وهو الحجم المشمول في العرض المجاني دائماً Always Free، ويحتوي على 1 جيجابايت رام).
قرص الإقلاع ونظام التشغيل (Boot Disk):
انزل لأسفل واضغط على زر Change في قسم Boot disk.
Operating system: اختر Ubuntu.
Version: اختر Ubuntu 22.04 LTS.
Boot disk type: اختر Standard persistent disk (لتدخل ضمن العرض المجاني).
Size: اكتب 30 جيجابايت (الحد الأقصى المجاني).
اضغط على Select.
جدار الحماية (Firewall):
في قسم جدار الحماية، قم بتحديد الخيارين: Allow HTTP traffic و Allow HTTPS traffic (هذا مهم جداً لفتح المنفذين 80 و 443 لاستقبال اتصالات البروكسي والتمويه).
اضغط على زر Create بالأسفل.