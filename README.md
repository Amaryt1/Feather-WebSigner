# Feather WebSigner

واجهة ويب لتوقيع IPA محليًا داخل المتصفح باستخدام WebAssembly. لا يتم رفع P12 أو كلمة المرور أو MobileProvision أو IPA إلى خادم مركزي.

## المميزات

- تحميل P12 وMobileProvision وIPA من الهاتف أو الكمبيوتر.
- عرض اسم الملف وحجمه فور اختياره.
- سحب وإفلات الملفات على بطاقات الاختيار.
- تحميل محرك `zsign-wasm` بالطريقة المناسبة لـ Vite وGitHub Pages.
- قراءة `Info.plist` الثنائية عبر WASM واستخراج Bundle ID واسم الملف التنفيذي تلقائيًا.
- فحص IPA قبل التوقيع والتأكد من وجود `Payload/*.app` و`Info.plist` والملف التنفيذي.
- التحقق من بيانات التوقيع وإنشاء `WasmSigner` محليًا.
- استبدال `embedded.mobileprovision` بالملف الذي اختاره المستخدم.
- توقيع Mach-O الداخلي من Frameworks/Dylibs قبل توقيع التطبيق الرئيسي.
- إعادة بناء `CodeResources` وكتابة `_CodeSignature/CodeResources`.
- توقيع الملف التنفيذي الرئيسي أخيرًا باستخدام Bundle ID وInfo.plist وCodeResources النهائية.
- إنشاء IPA موقعة داخل المتصفح وإتاحة تنزيلها مباشرة.
- إظهار تقدم العملية ورسائل الخطأ بدلًا من ترك الواجهة معلقة.
- تنظيف رابط التنزيل المؤقت عند إغلاق الصفحة.
- عدم إنتاج IPA مضللة عند اكتشاف App Extensions (`.appex`) تحتاج Provisioning مستقلًا؛ يتم إيقاف العملية برسالة واضحة بدل إنشاء ملف غير صالح.

## التشغيل محليًا

```bash
npm install
npm run dev
```

## البناء

```bash
npm run build
```

ينتج Vite مجلد `dist` الجاهز للنشر.

## GitHub Pages

المشروع يحتوي على GitHub Actions للنشر التلقائي عند الدفع إلى `main`. لا يستخدم workflow ذاكرة npm cache لأن المستودع لا يحتاج lockfile لتشغيل `npm install`.

## الأمان والخصوصية

- لا تضع أي P12 أو MobileProvision أو كلمات مرور داخل المستودع.
- الملفات المختارة تبقى في ذاكرة المتصفح أثناء العملية.
- لا توجد واجهة رفع إلى API أو خادم توقيع.
- استخدم فقط شهادات وملفات Provisioning التي تملك حق استخدامها.

## القيود المهمة

- IPA التي تحتوي على App Extensions (`.appex`) تحتاج ملف Provisioning مناسبًا لكل Bundle؛ هذه النسخة توقف العملية بدل إنشاء IPA غير صالحة.
- التوقيع لا يتجاوز قيود Apple المتعلقة بالـProvisioning أو الأجهزة المسجلة أو صلاحية الشهادة.
- التثبيت عبر `itms-services` يحتاج manifest مستضافًا عبر HTTPS.

## التقنية

- Vite
- `@jveko/zsign-wasm`
- `fflate`
