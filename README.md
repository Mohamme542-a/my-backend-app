# Qarfash — جاهز للنشر

## ملفات الواجهة (GitHub Pages)
- `index.html` — تطبيق المستخدم
- `admin.html` — لوحة الأدمن (مفتوحة بدون كلمة سر)

ارفعهما إلى مستودع GitHub وفعّل GitHub Pages من Settings → Pages.

## الباك-إند (Render)
- `server.js`, `package.json`, `render.yaml`

### خطوات النشر على Render
1. ارفع المجلد إلى GitHub.
2. على Render: **New → Blueprint** → اختر المستودع.
3. عبّئ **Environment Variables** التالية:

| المتغير | القيمة |
|---|---|
| `JWT_SECRET` | يُولَّد تلقائياً |
| `APP_INTEGRITY_HASH` | `2ad9fc388b30f1314d07654cae91106981bcff7aa61448264e924666e47487bb` |
| `FIREBASE_DB_URL` | `https://xxx-default-rtdb.firebaseio.com` |
| `FIREBASE_DB_SECRET` | (اختياري) سر قاعدة البيانات |
| `CLOUDINARY_CLOUD_NAME` | `dbcqz0yae` |
| `CLOUDINARY_UPLOAD_PRESET` | `anasheed_unsigned` |
| `SELF_URL` | `https://my-backend-app-lte3.onrender.com` |

> ملاحظة: الرفع يتم مباشرة من المتصفح إلى Cloudinary بواسطة الـ unsigned preset، فلا حاجة إلى `CLOUDINARY_API_KEY` أو `CLOUDINARY_API_SECRET`.

## ملاحظات أمان
- لوحة الأدمن مفتوحة بدون كلمة سر (حسب الطلب). احمها بطبقة وصول إذا أردت (مثل Cloudflare Access أو Basic-Auth في GitHub Pages عبر مزود وسيط).
- نقاط `/api/admin/*` لا تتطلب JWT.
- نقاط المستخدم `/api/data`, `/api/sections`, `/api/side-menu`, `/api/app-status` لا تزال محمية بتوقيع HMAC + JWT.

## نقاط الاتصال
- `GET /health` — فحص صحة
- `GET /api/cloudinary/config` — قراءة إعدادات Cloudinary
- `POST /auth/handshake`, `POST /auth/refresh`
- `GET /api/{data,sections,side-menu,app-status}` — موقّعة (للمستخدم)
- `GET|POST|PUT|DELETE /api/admin/*` — مفتوحة (للأدمن)
