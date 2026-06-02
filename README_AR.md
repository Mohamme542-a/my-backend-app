# دليل التشغيل والربط — نسخة أثير الآمنة v4.0

هذا الدليل يشرح كيفية تشغيل التطبيق ودمج لوحة الإدارة `admin.html` مع
النظام الأمني الجديد (JWT + CSRF + Refresh Tokens) **دون استبدال** الواجهات
الأصلية للمستخدم.

---

## 1) محتويات المجلد

```
secure/
├─ server-secure.js          ← السيرفر الرئيسي (يشغّل كل شيء)
├─ package.json
├─ .env.example              ← انسخه إلى .env واملأه
├─ middleware/
│   ├─ security.js           ← Helmet + CORS + Rate-limit + CSRF + Sanitize
│   ├─ auth.js               ← JWT (access 15د / refresh 30ي) + bcrypt
│   ├─ audit.js              ← سجل تدقيق append-only في ./logs
│   └─ upload.js             ← رفع موقَّع إلى Cloudinary + قائمة بيضاء
├─ routes/
│   ├─ admin-auth.js         ← /api/admin/auth/{login,refresh,logout,me}
│   ├─ admin.js              ← كل عمليات الإدارة (محمية)
│   └─ public.js             ← /api/{data,sections,posts,stream,...} للمستخدم
├─ lib/  utils/  scripts/    ← أدوات داخلية
└─ public/
    ├─ index.html            ← واجهة المستخدم (بلا تسجيل دخول)
    ├─ admin.html            ← لوحة الإدارة (تتطلب JWT)
    └─ admin-login.html      ← شاشة تسجيل دخول الأدمن
```

---

## 2) التثبيت السريع

```bash
cd secure
npm install
npm run genkeys     # يُولّد مفاتيح سرّية 50 خانة hex
npm run hash "كلمة-مرور-طويلة-لا-تقل-عن-16-حرف"   # يطبع ADMIN_PASSWORD_HASH
cp .env.example .env
# ثم افتح .env والصق كل المفاتيح + بيانات Firebase / Cloudinary
npm start
```

ستجد التطبيق على: `http://localhost:3000`

| الصفحة | الرابط |
|---|---|
| واجهة المستخدم | `/`  أو  `/index.html` |
| لوحة الإدارة | `/admin-login.html` ← ثم تحويل تلقائي إلى `/admin.html` |

---

## 3) متغيرات البيئة المطلوبة (`.env`)

```env
NODE_ENV=production
PORT=3000
TRUST_PROXY=1

# يُولَّد عبر: npm run genkeys (طول 50 حرف hex لكل واحد)
JWT_ACCESS_SECRET=...
JWT_REFRESH_SECRET=...
CSRF_SECRET=...
COOKIE_SECRET=...
SESSION_SECRET=...

# الأدمن
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=$2a$12$....   # ناتج: npm run hash "..."

# Firebase Realtime DB
FIREBASE_DB_URL=https://<your-db>.firebaseio.com
FIREBASE_AUTH_TOKEN=...

# Cloudinary (رفع موقَّع فقط)
CLOUDINARY_CLOUD_NAME=...
CLOUDINARY_API_KEY=...
CLOUDINARY_API_SECRET=...

# CORS — قائمة بيضاء لنطاقاتك (مفصولة بفواصل)
ALLOWED_ORIGINS=https://your-domain.com,https://www.your-domain.com
```

> **مهم:** لا تضع أي مفتاح سري داخل `index.html` أو `admin.html`. كل المفاتيح
> تبقى في `.env` على السيرفر فقط.

---

## 4) كيف يتم ربط لوحة الإدارة بنظام JWT؟

### الدورة الكاملة

```
المستخدم يفتح /admin.html
   │
   ├─ لا يوجد admin_access في sessionStorage
   │   └─► تحويل فوري إلى /admin-login.html
   │
   └─ يوجد token
       ├─ admin.html ينادي /api/admin/auth/me للتحقق
       │   ├─ 200 ← تظهر اللوحة
       │   └─ 401 ← محاولة /api/admin/auth/refresh تلقائياً
       │           ├─ نجاح ← يكمل العمل
       │           └─ فشل ← /admin-login.html
       │
       └─ كل طلب لـ /api/admin/* يحمل:
           Authorization: Bearer <access_token>
           X-CSRF-Token:  <token من /api/csrf>
           credentials:   include   (لإرسال كوكي refresh الموقَّع)
```

### بعد تسجيل الدخول من `admin-login.html`

1. السيرفر يتحقق من اسم المستخدم + bcrypt على كلمة المرور.
2. يُرجِع `accessToken` (15 دقيقة) ويزرع كوكي `rt` (refresh, 30 يوم,
   `httpOnly` + `Secure` + `SameSite=Strict` + موقَّع).
3. شاشة الدخول تحفظ الـ access في `sessionStorage` فقط (يُمسح عند إغلاق
   التبويب) ثم تحوّل إلى `/admin.html`.
4. `admin.html` لا يفتح إطلاقاً بدون access صالح.

### تجديد الجلسة تلقائياً

كل طلب يحصل على `401` يُعيد `admin.html` المحاولة مرة واحدة عبر
`POST /api/admin/auth/refresh` ثم يُعيد الطلب الأصلي. عند فشل التجديد
تُمسح كل البيانات ويُحوَّل المستخدم إلى صفحة الدخول.

### تسجيل الخروج

```js
await api('/api/admin/auth/logout', { method:'POST' });
sessionStorage.clear();
location.replace('/admin-login.html');
```

---

## 5) إصلاح مشكلة تشغيل الفيديو

تم تعديل `index.html` ليمرّر كل روابط الوسائط عبر:

```
GET /api/stream?u=<encoded-url>&mime=video/mp4
```

هذا الـ proxy في `routes/public.js`:
- يدعم **Range Requests** (يحل مشكلة "تعذّر التشغيل" على الموبايل).
- يضبط `Content-Type` الصحيح لـ `.mp4 / .webm / .mov / .m3u8 / mp3 / m4a`.
- يضيف `Accept-Ranges: bytes` و `Cross-Origin-Resource-Policy: cross-origin`.
- يلغي مشاكل CORS تماماً لأن المتصفح يتحدث مع نفس النطاق.

---

## 6) رفع الملفات (Cloudinary موقَّع)

لم نعد نستخدم `upload_preset` المكشوف. الآن:

1. لوحة الإدارة تنادي `POST /api/admin/cloudinary/sign` (محمي بـ JWT+CSRF).
2. السيرفر يوقّع المعاملات بـ `CLOUDINARY_API_SECRET` ويُرجع توقيعاً صالحاً
   لـ 10 دقائق فقط.
3. المتصفح يرفع الملف مباشرة إلى Cloudinary بهذا التوقيع.
4. القائمة البيضاء في `middleware/upload.js` ترفض أي امتداد خطر
   (`.exe`, `.js`, `.html`, `.svg`, …).

كل عناصر القسم/المنشور تحتوي الآن على: `title`, `cover`, `caption`, `tags`
بالإضافة إلى `url` — تماماً كالمنشورات.

---

## 7) نشر على Render / Railway / VPS

1. ارفع المجلد كاملاً.
2. اضبط جميع متغيرات `.env` في لوحة المنصة.
3. أمر التشغيل: `npm start`.
4. اضبط `ALLOWED_ORIGINS` على نطاقك الفعلي.
5. تأكد من تشغيل HTTPS (السيرفر يُجبر التحويل في الإنتاج).

---

## 8) مسارات API السريعة

### عامة (للمستخدم — بدون توكن)
- `GET  /api/data`           قائمة الأناشيد
- `GET  /api/sections`       الأقسام
- `GET  /api/posts`          المنشورات (يدعم `?q=...`)
- `GET  /api/side-menu`      القائمة الجانبية
- `GET  /api/app-config`     اسم التطبيق + الألوان + الخط + روابط السوشيال
- `GET  /api/app-status`     مفتاح الإيقاف
- `GET  /api/stream?u=...`   بثّ الوسائط (Range)
- `POST /api/posts/:id/view` زيادة المشاهدات

### إدارية (تتطلب JWT + CSRF)
- `POST /api/admin/auth/login` `{username,password}` ← `{accessToken}`
- `POST /api/admin/auth/refresh` (يقرأ كوكي `rt`)
- `POST /api/admin/auth/logout`
- `GET  /api/admin/auth/me`
- `GET/POST/PUT/DELETE /api/admin/posts[...]`
- `GET/POST/PUT/DELETE /api/admin/sections[...]`
- `GET/POST/PUT/DELETE /api/admin/side-menu[...]`
- `GET/POST/PUT/DELETE /api/admin/anasheed[...]`
- `GET/POST /api/admin/app-config`
- `GET/POST /api/admin/app-status`
- `POST /api/admin/cloudinary/sign`

---

## 9) ملاحظات أمنية

- `index.html` **مفتوح بدون أي توكن** — موجَّه للمستخدمين النهائيين.
- `admin.html` **محمي بالكامل** — مغلق إن لم يوجد access صحيح.
- كل عملية إدارية تُسجَّل في `./logs/audit-YYYY-MM-DD.log` (IP, UA, status).
- كلمة المرور لا تُحفظ نصاً أبداً — فقط `bcrypt` بتكلفة 12.
- كل المفاتيح السرية 50 خانة hex (`npm run genkeys`).

تم بحمد الله — جاهز للإنتاج.
