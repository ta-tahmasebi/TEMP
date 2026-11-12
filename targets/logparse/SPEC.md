# logparse specification

`logparse` یک رکورد لاگ را از stdin می‌خواند. دو قالب `LEVEL|MESSAGE` و
`LEVEL:MESSAGE` معادل‌اند. سطح فقط یکی از `INFO`، `WARN` یا `ERROR` است و پیام
می‌تواند صفر تا ۳۱ نویسه داشته باشد. خروجی موفق `[LEVEL] MESSAGE` و کد خروج صفر
است. ورودی نامعتبر باید بدون crash با پیام خطا و کد ۲ رد شود.
