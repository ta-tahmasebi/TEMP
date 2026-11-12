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

ابزار چهار باینری می‌سازد: نسخهٔ پایه و وصله‌شده، هرکدام در حالت release و
sanitized. همهٔ ورودی‌های معتبر، مرزی، نامعتبر و امنیتی روی هر چهار باینری
اجرا می‌شوند. اجراها با Bubblewrap، محدودیت حافظه، CPU، فرایند و زمان ایزوله
هستند.

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
