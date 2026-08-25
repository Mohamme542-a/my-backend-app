# تقرير ترحيل Archive v5.0 — إصلاحات أمنية وهيكلية

## ✅ ما تم إصلاحه

### 1. حماية admin.html على مستوى الخادم
- تم تفعيل middleware `protectAdminPages` في `server-secure.js` قبل خدمة الملفات الثابتة.
- يتم التحقق من JWT (`Authorization: Bearer`) أو من `refresh token` المُوقَّع في الكوكي.
- في حال عدم وجود توكن صالح → إعادة توجيه 302 إلى `/admin-login.html`.
- لا يمكن الوصول لـ `admin.html` بمجرد معرفة الرابط.

### 2. endpoints مفقودة أُضيفت
- `GET  /api/admin/data` — يجلب كل البيانات (config/status/sections/posts/anasheed/sideMenu) دفعة واحدة لتحميل لوحة الأدمن.
- `POST /api/admin/anasheed/broadcast-cover` — تعيين غلاف واحد لكل الأناشيد (مع خيار `onlyMissing`).

### 3. csrfToken يعود مع تسجيل الدخول
- `POST /api/admin/auth/login` يُرجِع الآن `{ accessToken, csrfToken, expiresIn, user }`.
- `POST /api/admin/auth/refresh` يُرجِع كذلك `csrfToken` المحدّث.
- `admin.html` يحفظه في `sessionStorage` ويُرسله مع كل طلب في رأس `X-CSRF-Token`.

### 4. CORS أكثر مرونة
- وضع التطوير: السماح تلقائيًا بـ `localhost`/`127.0.0.1` (أي منفذ).
- وضع الإنتاج: يجب تحديد `ALLOWED_ORIGINS` بشكل صريح؛ بدون ذلك يُرفض كل origin خارجي.
- لا يُكسر هذا أي طلب same-origin (بدون رأس Origin).

### 5. Service Worker + js/api.js
- `/sw.js` يقوم بـ network-first لـ `/api/*` و stale-while-revalidate للأصول.
- يتجاهل تمامًا `/admin*` و `/api/admin*` و `/api/stream` لتفادي مخاطر التخزين المؤقت للوسائط الحساسة.
- تم توحيد `normalizeMediaUrl` داخل واجهة Archive لتمرير وسائط HTTP عبر `/api/stream`، وأزيلت إحالة `/js/api.js` غير الموجودة.

### 6. ملاحظات لم تُنفَّذ (مقصودة)
- ما زالت الواجهة في ملفات HTML كبيرة لتقليل مخاطر تغيير نموذج البيانات القديم، مع إضافة اختبار دخان قابل للتشغيل عبر `npm test`.
- لم يُضَف SRI لـ `hls.js` — يُستحسن استضافته محليًا في `public/vendor/hls.min.js` لاحقًا.

## كيفية النشر
```bash
npm install
npm run genkeys   # ينشئ مفاتيح 50 hex
npm run hash      # ينشئ ADMIN_PASSWORD_HASH
# املأ .env ثم:
NODE_ENV=production node server-secure.js
```

## متغيرات البيئة المطلوبة (إنتاج)
- `JWT_ACCESS_SECRET` (>= 32 حرف)
- `JWT_REFRESH_SECRET` (>= 32 حرف)
- `CSRF_SECRET` `COOKIE_SECRET`
- `ADMIN_USERNAME` `ADMIN_PASSWORD_HASH`
- `ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com`
- `FORCE_HTTPS=true`
