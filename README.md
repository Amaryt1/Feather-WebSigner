# Feather WebSigner

واجهة ويب لتوقيع IPA محليًا داخل المتصفح باستخدام WebAssembly، دون رفع P12 أو كلمة المرور أو IPA إلى خادم مركزي.

## التشغيل

```bash
npm install
npm run dev
```

لإنشاء نسخة النشر:

```bash
npm run build
```

ثم انشر مجلد `dist` على استضافة ملفات ثابتة مثل GitHub Pages أو Cloudflare Pages.

## ملاحظات

- استخدم فقط الشهادات وملفات MobileProvision التي تملك حق استخدامها.
- هذه النسخة تستهدف IPA التي تحتوي على `Payload/*.app` وتوقّع الملف التنفيذي الرئيسي.
- التطبيقات التي تحتوي على Extensions أو Frameworks متعددة قد تحتاج توقيعًا متداخلًا لكل Bundle.
- التوقيع لا يتجاوز قيود Apple المتعلقة بالـProvisioning أو الأجهزة المسجلة.
- التثبيت عبر `itms-services` يحتاج manifest مستضافًا عبر HTTPS.

المشروع يعتمد على `@jveko/zsign-wasm` و`fflate` و`plist`.
