# 🛡️ MOHAMMED v3 — Comprehensive Security Framework & Recon Orchestrator

**MOHAMMED v3** هو محرك فحص أمني واستكشاف أهداف شمولية متطور، مبرمج بالكامل بلغة **Go**. يهدف Framework إلى استبدال السكربتات العشوائية بنظام مجمع (Compiled)، آمن في إدارة الذاكرة، ويتعامل بمرونة فائقة مع المتزامنات (Concurrency). 

يقوم المحرك بتنظيم وإدارة **38+ أداة أمنية خارجية** عبر 29 مرحلة متسلسلة ودقيقة بدون تكرار أو عشوائية، مع إمكانية تحويل حركة المرور بالكامل إلى **Burp Suite** ودعم التحليل الذكي للثغرات باستخدام **Ollama AI (Gemma 2 / Llama 3)**.

---

## 📐 الهيكل الشامل للمشروع (Directory & File Architecture)

```
mohammed-v3/
├── cmd/
│   └── mohammed/
│       └── main.go              # نقطة الإدخال الرئيسية (CLI Engine Entry Point)
├── pkg/
│   ├── config/
│   │   └── config.go            # إدارة النطاق (Scope)، الملفات التكوينية، ومفاتيح API
│   ├── engine/
│   │   └── engine.go            # المحرك المركزي، إدارة الحالات (State)، والعداد الحي (1-Second Ticker)
│   ├── governor/
│   │   └── governor.go          # منظم السرعة ومعدلات الطلبات والتكيف مع WAF/Cloudflare
│   ├── phases/
│   │   ├── phases.go            # المراحل (01 إلى 14): الاستكشاف، جمع Subdomains، وفحص DNS
│   │   └── phases_vuln.go       # المراحل (15 إلى 29): فحص الثغرات، الثغرات المتقدمة والتقارير
│   ├── proxy/
│   │   └── proxy.go             # مدير البروكسي لإدارة وتوجيه الترافيك لـ Burp Suite
│   └── runner/
│       └── runner.go            # منفذ الأدوات بأمان (Setpgid/Process Group Isolation & Timeouts)
├── config.yaml                  # ملف التكوين العام ومفاتيح APIs و Ollama Configuration
├── scope.txt                    # قائمة النطاقات والقواعد المسموحة والمستبعدة
├── setup.sh                     # السكربت التلقائي لتجهيز وتنزيل كافة الأدوات والربط بالـ PATH
├── verify.sh                    # سكربت التحقق والاختبار الذاتي لكافة مكونات النظام
└── README.md                    # هذا الدليل التوضيحي الشامل
```

---

## ⚡ المميزات والتقنيات المحورية في MOHAMMED v3

### 1. العداد الزمكاني الحي (Live 1-Second Ticker)
- يعمل في خلفية مستقلة (Goroutine) يحدّث حالة الفحص والوقت المنقضي بالثانية على سطر واحد ثابت بدون تلوث شاشة المخرجات (`\r\033[K`).
- محمي بواسطة `sync.Mutex` لمنع تداخل نصوص الأدوات مع العداد.

### 2. إدارة العمليات الشديدة والأمان من التعليق (Process Group Isolation)
- تستخدم أداة `runner.go` خيار `SysProcAttr: &syscall.SysProcAttr{Setpgid: true}`.
- في حال تجاوز أي أداة (مثل `amass` أو `bbot`) الوقت المحدد لها، يتم إنهاء مجموعة العمليات (Process Group) بالكامل عبر `syscall.Kill(-pgid, SIGKILL)` لضمان عدم بقاء عمليات معلقة في الخلفية.

### 3. التكيف التلقائي مع حظر WAF/Cloudflare (Adaptive Rate Governor)
- مراقبة ردود الأفعال ورسائل الحظر؛ عند كشف WAF، تتباطأ الأداة تلقائياً عبر `Governor.ReportWAF()` لتقليل التزامن وحماية IP الفاحص من الحجب.

### 4. الربط المباشر مع Burp Suite
- إمكانية تمرير `--burp http://127.0.0.1:8080`؛ تدمج الأداة بيئة البروكسي (`HTTP_PROXY` / `HTTPS_PROXY`) في كافة خوادم وأدوات الفحص (`nuclei`, `ffuf`, `httpx`, `dalfox`) لتمرير الترافيك لبرنامج Burp لتسليط الضوء على الطلبات ودراستها.

---

## 🤖 دمج الذكاء الاصطناعي المحلي (Ollama AI Integration)

تحتوي الأداة في ملف `config.yaml` على قسم خاص بنماذج الذكاء الاصطناعي المحلية عبر **Ollama**:

```yaml
ollama:
  enabled: true
  endpoint: "http://localhost:11434"
  model: "gemma:2b"       # أو llama3 / qwen2.5
  timeout: 30
```

### لماذا تم استخدام نموذج خفيف مثل Gemma / Llama عبر Ollama؟
1. **تصنيف الثغرات والحد من الإيجابيات الزائفة (AI Vulnerability Triage):**
   عند كشف ثغرة من أدوات مثل `subzy` أو `nuclei` أو `custom checks`، يمرر الكود نص الاستجابة والـ Evidence إلى نموذج Ollama الخفيف للتأكد مما إذا كانت الثغرة حقيقية وتستحق إدراجها بمرتبة **Critical/High**، أم أنها مجرد رد عادي من السيرفر.
2. **العمل المحلي 100% وبدون تكلفة:**
   عدم إرسال أي بيانات أو طلبات إلى سيرفرات خارجية (الحفاظ على السرية التامة للأهداف).

---

## 🔑 التكوين ومفاتيح API (`config.yaml`)

يتم إدخال المفاتيح لتفعيل مصادر الاستخبارات السلبية (OSINT):

```yaml
api_keys:
  github: "ghp_xxxxxxxxxxxx"
  shodan: "API_KEY_HERE"
  virustotal: "API_KEY_HERE"
  alienvault: "API_KEY_HERE"
  securitytrails: "API_KEY_HERE"
  chaos: "API_KEY_HERE"
  censys: "API_KEY_HERE"

ollama:
  enabled: true
  endpoint: "http://localhost:11434"
  model: "gemma:2b"
```

---

## 🎯 قواعد النطاق (`scope.txt`)

يدعم الملف إضافة النطاقات والقواعد؛ والنطاقات المستبعدة تُسبق بصلامة بعلامة `-`:

```txt
# Target Domains
whatnot.com
api.whatnot.com

# Out of Scope (Will be excluded strictly)
-staging.whatnot.com
-dev.whatnot.com
```

---

## 📋 الدليل التفصيلي للمراحل الـ 29 (The 29 Scan Phases)

1. **Phase 01: Scope Validation** — التحقق من النطاقات والقواعد واستبعاد الخارجي.
2. **Phase 02: OSINT Gathering** — الاستعلام من Shodan, VirusTotal, SecurityTrails, AlienVault, crt.sh, HackerTarget.
3. **Phase 03: Passive Subdomain Enum** — تشغيل `subfinder`, `amass`, `bbot`, `assetfinder`, `findomain` ودمج النتائج.
4. **Phase 04: Active Subdomain Bruteforce** — التوليد عبر `dnsgen` والتأكيد عبر `puredns`.
5. **Phase 05: DNS Resolution & Enrichment** — حل وتأكيد العناوين المستجيبة عبر `dnsx` وتصفية الـ Wildcards.
6. **Phase 06: Subdomain Takeover Check** — فحص CNAMEs التالفة عبر `subzy`.
7. **Phase 07: HTTP Probing & Tech Detection** — البصمة التقنية وفحص الاستجابة عبر `httpx`.
8. **Phase 08: TLS/SSL Analysis** — فحص الشهادات والتشفير المنتهي عبر `tlsx`.
9. **Phase 09: Port Scanning** — فحص المنافذ المفتوحة عبر `naabu` و `nmap`.
10. **Phase 10: Wayback Archive Mining** — استخراج الروابط الأرشيفية القديمة عبر `gau` و `waybackurls`.
11. **Phase 11: Web Crawling & Spidering** — الزحف العميق واستخراج الروابط عبر `katana` و `gospider`.
12. **Phase 12: JS Analysis & Secret Extraction** — استخراج ملفات JavaScript وفحصها بأنماط Regex لكشف مفاتيح API والتوكنات.
13. **Phase 13: Parameter Discovery** — استخراج المتغيرات والبارامترات عبر `paramspider` و `arjun`.
14. **Phase 14: CORS Misconfiguration Check** — فحص ثغرات مشاركة الموارد غير الآمنة (CORS Origin Reflection).
15. **Phase 15: Cloud & Bucket Recon** — كشف الحاويات المفتوحة والسلاسل السحابية عبر `cloud_enum` و `s3scanner`.
16. **Phase 16: Directory Fuzzing** — التخمين على المسارات والملفات عبر `ffuf`.
17. **Phase 17: Vulnerability Scanning (Nuclei)** — الفحص الشامل للقوالب عبر `nuclei`.
18. **Phase 18: XSS Detection** — فحص حقن السكربتات عبر `dalfox` و `kxss`.
19. **Phase 19: SQL Injection Analysis** — فحص حقن قواعد البيانات عبر `sqlmap` و `ghauri`.
20. **Phase 20: SSRF Scanning** — كشف ثغرات طلب السيرفر الجانبي عبر `nuclei ssrf` و `interact.sh`.
21. **Phase 21: Open Redirect Testing** — فحص إعادة التوجيه المفتوح على روابط البارامترات.
22. **Phase 22: 403/401 Bypass Testing** — محاولة تجاوز صفحات الحظر عبر `dontgo403`.
23. **Phase 23: API Route Discovery** — اكتشاف مسارات الـ APIs عبر `kiterunner`.
24. **Phase 24: CRLF Injection Check** — فحص ثغرات حقن الهيدر عبر `crlfuzz`.
25. **Phase 25: HTTP Request Smuggling** — فحص ثغرات تهريب الطلبات عبر `smuggler`.
26. **Phase 26: Sensitive File Exposure** — فحص الملفات الحساسة المكتشوفة (`.git`, `.env`, backup files).
27. **Phase 27: Email Security Verification** — فحص سجلات الحماية للبريد الإلكتروني (`SPF`, `DKIM`, `DMARC`).
28. **Phase 28: Prototype Pollution Scan** — فحص ثغرات تلوث الكائنات بـ JavaScript.
29. **Phase 29: Final Report Generation** — تجميع كافة النتائج وإنشاء تقرير شامل بنماذج Markdown و JSON.

---

## 🛠️ أوامر التجهيز والتشغيل (Commands Reference)

### 1. التجهيز الأولي وتنزيل الأدوات:
```bash
bash setup.sh
```

### 2. فحص الجاهزية والأدوات (Doctor Check):
```bash
./mohammed doctor
```

### 3. تشغيل فحص شامل على هدف كبير (مع Burp Suite):
```bash
./mohammed scan -s scope.txt -c config.yaml --profile large --burp http://172.30.48.1:8080
```

### 4. تشغيل فحص سريع متوسط:
```bash
./mohammed scan -s scope.txt -c config.yaml --profile medium
```

### 5. تشغيل أداة التحقق والتأكد الذاتي من الكود والأدوات:
```bash
bash verify.sh
```
