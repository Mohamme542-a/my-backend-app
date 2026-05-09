# Qarfash API — Secure Backend (v2.0)

Backend وسيط آمن بين تطبيق Qarfash و Firebase + Cloudinary، مع توقيع HMAC، JWT، Rate Limit، Anti-Replay، وفحص نزاهة التطبيق.

## النشر على Render

1. ارفع المجلد إلى GitHub.
2. على Render: New → Blueprint → اختر المستودع.
3. عبّئ القيم التالية في **Environment Variables**:

| المتغير | الوصف | مثال |
|---|---|---|
| `HMAC_SECRET` | يولّد تلقائياً | (auto) |
| `JWT_SECRET` | يولّد تلقائياً | (auto) |
| `ADMIN_PASSWORD_HASH` | SHA-256 لكلمة سر الأدمن | شغّل الأمر أدناه |
| `APP_INTEGRITY_HASH` | بصمة التطبيق | `2ad9fc38…7487bb` (موجودة) |
| `ALLOWED_ORIGINS` | قائمة الأصول المسموحة | `*` (للـ WebView) |
| `FIREBASE_DB_URL` | رابط Realtime DB | `https://xxx-default-rtdb.firebaseio.com` |
| `FIREBASE_DB_SECRET` | (اختياري) سر DB | — |
| `CLOUDINARY_CLOUD_NAME` | اسم سحابة Cloudinary | `dxxxx` |
| `CLOUDINARY_API_KEY` | مفتاح Cloudinary | `123…` |
| `CLOUDINARY_API_SECRET` | سر Cloudinary | `abc…` |
| `CLOUDINARY_UPLOAD_PRESET` | اسم الـ preset | `qarfash_unsigned` |
| `RATE_LIMIT_IP` | طلب/دقيقة لكل IP | `60` |
| `RATE_LIMIT_DEVICE` | طلب/دقيقة لكل جهاز | `120` |
| `SELF_URL` | رابط الخدمة لمنع النوم | `https://qarfash-api.onrender.com` |

### توليد ADMIN_PASSWORD_HASH
```bash
node -e "console.log(require('crypto').createHash('sha256').update('K#p9\$vL2&mN5*xQ8!zR1').digest('hex'))"
```

## نقاط الاتصال

### عامة
- `GET /health` — فحص صحة الخدمة (بدون توقيع)
- `POST /auth/handshake` — يبدأ جلسة، يصدر `accessToken` (5د) + `refreshToken` (7 أيام)
- `POST /auth/refresh` — تجديد الـ access token

### موقّعة (تتطلب HMAC + access token)
- `GET /api/data` — جميع الأناشيد
- `GET /api/sections` — الأقسام
- `GET /api/side-menu` — عناصر القائمة الجانبية
- `GET /api/app-status` — حالة التطبيق + إصدار التحديث

### أدمن (تتطلب admin JWT)
- `POST /api/admin/login` — `{ passwordHash }` → admin token
- `POST /api/admin/sections` — إنشاء قسم
- `DELETE /api/admin/sections/:id`
- `POST /api/admin/anasheed` — إضافة نشيد
- `DELETE /api/admin/anasheed/:id`
- `POST /api/admin/side-menu` — إضافة عنصر قائمة
- `DELETE /api/admin/side-menu/:id`
- `POST /api/admin/app-status` — `{ disabled, message, version, updateUrl }`
- `POST /api/admin/upload-sign` — يوقّع رفع Cloudinary

## بروتوكول التوقيع (HMAC)

كل طلب موقّع يحوي:
- `X-Timestamp` — Unix ms
- `X-Nonce` — UUID فريد
- `X-Device-Id` — بصمة الجهاز
- `X-Signature` — `HMAC_SHA256(method|path|timestamp|nonce|deviceId|sha256(body), HMAC_SECRET)`
- `Authorization: Bearer <accessToken>`

التحقق:
- timestamp drift ≤ 30s
- nonce لم يُستخدم خلال 60s
- توقيع صحيح
- access token صالح
