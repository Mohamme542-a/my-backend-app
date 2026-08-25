# Archive — دليل التشغيل والربط

**Archive** منصة أرشيف وسائط عربية متجاوبة، مبنية على Express وFirebase Realtime Database، مع لوحة إدارة محمية ورفع موقّع إلى Cloudinary. تدعم المنشورات والأقسام والقوائم الجانبية والصور والصوت والفيديو وملفات PDF والروابط المضمنة.

## التشغيل السريع

```bash
cp .env.example .env
npm install
npm run genkeys
npm run hash "كلمة-مرور-طويلة-لا-تقل-عن-16-حرف"
# ضع القيم الناتجة وإعدادات Firebase وCloudinary داخل .env
npm start
```

افتح `/` لواجهة المستخدم، أو `/admin-login.html` لتسجيل الدخول إلى لوحة الإدارة. الوصول المباشر إلى `/admin.html` يُعاد توجيهه إلى صفحة الدخول ما لم توجد جلسة مدير صالحة.

## ما تم إصلاحه

تم تفعيل الحارس العالمي لجميع مسارات الإدارة، وربط بيانات المدير بمتغيرات البيئة بدل القيم المثبتة، وإضافة تحميل `.env` عبر `dotenv`، وإزالة سجلات تسجيل الدخول التفصيلية. كما أُصلحت سياسة CSP لتسمح بإطارات منصات الوسائط المعروفة فقط، وأُصلح عامل الخدمة ليستخدم إصدار Archive ولا يطلب ملفًا غير موجود.

تعتمد الوسائط المباشرة على `/api/stream` مع دعم `Range` و`HEAD` واشتقاق MIME من الرابط أو تلميح النوع أو اسم الملف في `Content-Disposition`. هذا مهم للملفات التي يعيد مزودها `application/octet-stream`. أما PDF فيُعرض داخل عارض من نفس النطاق بدل الاعتماد الإجباري على Google Viewer، مع رابط تنزيل بديل. وتستخدم روابط YouTube وVimeo وFacebook وTikTok وDailymotion وSoundCloud وTwitch وArchive.org مشغلات مضمّنة عند توافق الرابط.

## الرفع

الرفع يتم إلى Cloudinary من خلال توقيع قصير العمر يصدره الخادم بعد تحقق JWT وCSRF. تقبل الواجهة الصور والصوت والفيديو وPDF حتى **200MB للملف الواحد**، وتثبت MIME للملفات التي لا يرسل المتصفح نوعها، كما تتحقق من الاستجابة حتى لا يبقى مؤشر الرفع عالقًا.

لا توجد مفاتيح لخدمات رفع خارجية داخل المتصفح. أزيل مسار FileLu السابق لأنه كان يحتوي مفتاحًا ثابتًا ويعتمد على CORS غير مضمون.

## متغيرات البيئة

```env
NODE_ENV=production
PORT=3000
TRUST_PROXY=1
FORCE_HTTPS=true

JWT_ACCESS_SECRET=...
JWT_REFRESH_SECRET=...
CSRF_SECRET=...
COOKIE_SECRET=...

ADMIN_USERNAME=archive-admin
ADMIN_PASSWORD_HASH=$2b$12$....

FIREBASE_DB_URL=https://<your-db>.firebaseio.com
FIREBASE_AUTH_TOKEN=...

CLOUDINARY_CLOUD_NAME=...
CLOUDINARY_API_KEY=...
CLOUDINARY_API_SECRET=...

ALLOWED_ORIGINS=https://your-domain.com
```

لا تضع أي مفتاح سري في `public/index.html` أو `public/admin.html`. يبقى `CLOUDINARY_API_SECRET` وهاش كلمة المرور وأسرار JWT على الخادم فقط.

## المسارات المهمة

| المجال | المسارات |
|---|---|
| عامة | `GET /healthz`, `/api/data`, `/api/sections`, `/api/side-menu`, `/api/posts`, `/api/app-config`, `/api/app-status` |
| الوسائط | `GET/HEAD /api/stream?u=<url>&type=<type>&mime=<mime>`, `GET /api/detect-type?u=<url>`, `GET /api/resolve?u=<url>` |
| مصادقة الإدارة | `POST /api/admin/auth/login`, `/refresh`, `/logout`, `GET /api/admin/auth/me` |
| إدارة المحتوى | CRUD للمنشورات والأقسام والأناشيد والقوائم الجانبية وإعدادات التطبيق |
| الرفع | `POST /api/admin/cloudinary/sign` |

كل مسارات إدارة البيانات تتطلب `Authorization: Bearer <accessToken>` و`X-CSRF-Token` مع إرسال الكوكيز. التوكن المتجدد يُحفظ في كوكي موقّعة و`httpOnly`.

## التحقق

يحتوي `AUDIT_ARCHIVE.md` على نتائج التدقيق الكامل قبل التعديل. للتحقق محليًا:

```bash
npm install --no-audit --no-fund
for f in server-secure.js lib/*.js middleware/*.js routes/*.js utils/*.js scripts/*.js; do node --check "$f"; done
```

ثم شغّل الخادم بقيم اختبار صحيحة وتحقق من `/healthz`، ومن إعادة توجيه `/admin.html` دون جلسة، ومن `/api/detect-type` و`/api/stream` لملف PDF عام.
