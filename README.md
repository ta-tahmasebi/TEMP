# dynAn minimal

یک اعتبارسنج پویای وصله‌های امنیتی برای برنامه‌های C/C++ روی Linux x86_64.
این شاخه فقط قابلیت‌های اجباری پروژه را نگه می‌دارد و رابط وب، LLM، فازینگ و
لایه‌های افزونه را حذف کرده است.

## اجرا

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/dynan doctor --config configs/confparse-correct.yaml
.venv/bin/dynan validate --config configs/confparse-correct.yaml --json-out result.json
```

فرمان `validate` به‌صورت پیش‌فرض پیشرفت build، اجرای تست‌ها، تحلیل، بازپخش و مسیر
شواهد را مرحله‌به‌مرحله نشان می‌دهد. برای دیدن نتیجهٔ تک‌تک تست‌ها `--verbose` و
برای خروجی تک‌خطی مناسب CI گزینهٔ `--quiet` را اضافه کنید. گزینهٔ
`--no-minimize` نیز فقط کوچک‌سازی ورودی خراب را غیرفعال می‌کند و بقیهٔ بررسی‌ها
همچنان انجام می‌شوند.

نمونهٔ خلاصهٔ نهایی:

```text
=== Validation result ===
Verdict     : VULN_REMAINS (exit code 10)
Meaning     : a security failure from the base version is still reproducible after the patch
Security    : VULN_REMAINS
Regressions : none
Analysis    : complete
Evidence    : .../.dynan/runs/<id>/results.json
```

ابزار چهار باینری می‌سازد: نسخهٔ پایه و وصله‌شده، هرکدام در حالت release و
sanitized. همهٔ ورودی‌های معتبر، مرزی، نامعتبر و امنیتی روی هر چهار باینری
اجرا می‌شوند. اجراها با Bubblewrap، محدودیت حافظه، CPU، فرایند و زمان ایزوله
هستند.

اگر kernel یا محیط CI موقتاً ساخت namespace را نپذیرد، ابزار خطای زیرساختی
Bubblewrap را از خطای واقعی build جدا می‌کند و اجرا را با محدودیت منابع ادامه
می‌دهد. این حالت در خروجی و JSON با `Isolation: degraded` ثبت می‌شود؛ بنابراین
کاهش سطح ایزوله‌سازی پنهان نمی‌ماند.

## خروجی

هر اجرا در `.dynan/runs/<id>/results.json` ذخیره می‌شود و شامل موارد زیر است:

- diff و توابع تغییرکرده؛
- خروجی، خطا، سیگنال و کد خروج هر تست؛
- نوع خطا، روش تشخیص و ارتباط stack trace با diff؛
- سه بازپخش، ورودی کوچک‌شده و بستهٔ بازتولید؛
- تست رگرسیون تولیدشده و نتیجهٔ اجرای مجدد آن روی هر دو نسخه؛
- وضعیت NX، PIE، RELRO و Stack Canary؛
- وضعیت مستقل امنیت، عملکرد و کامل‌بودن تحلیل.

کدهای خروج مطابق صورت پروژه‌اند:

| کد | نتیجه |
|---:|---|
| 0 | `PASS` |
| 10 | `VULN_REMAINS` یا `NEW_ISSUE` |
| 20 | `FUNC_REGRESSION` |
| 30 | `BUILD_OR_CONFIG_ERROR` |
| 40 | `INCONCLUSIVE` |

اولویت هم‌زمانی وضعیت‌ها `30 > 10 > 20 > 40 > 0` است.

## افزودن هدف جدید

فقط یک فایل تنظیمات و manifest تست لازم است. تنظیمات مسیر دو درخت منبع، فرمان
ساخت، مسیر باینری و روش تحویل ورودی را تعیین می‌کند. manifest باید معیار مستقل
خروجی و تست‌های `valid`، `boundary`، `invalid` و `security` را داشته باشد؛ منطق
ابزار به نام تابع، فایل یا وصلهٔ خاصی وابسته نیست.

## ساختار ساده

- `src/dynan/core.py`: کل pipeline، اجرا، تحلیل و گزارش؛
- `src/dynan/cli.py`: دو فرمان `doctor` و `validate`؛
- `configs/`: سناریوهای وصلهٔ درست، ناقص و regression؛
- `targets/`: منابع چهار نسخه و oracle مستقل؛
- `tests/`: تست‌های واحد و end-to-end.
