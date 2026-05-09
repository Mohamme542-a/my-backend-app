# Qarfash Anasheed - Backend API

وسيط (Proxy) آمن بين تطبيق WebView وقاعدة بيانات Firebase Realtime Database.
لا تحتوي الواجهة على أي مفاتيح Firebase — كل شيء مخفي في السيرفر.

## النشر على Render

1. أنشئ مستودع Git جديد وارفع هذا المجلد كاملاً.
2. على [render.com](https://render.com) → **New + → Web Service**.
3. اربط المستودع، ثم اختر:
   - **Environment:** Node
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. أضف متغيرات البيئة في صفحة الـ Environment (انظر الجدول أدناه).
5. بعد أول نشر ناجح، انسخ رابط الخدمة (مثل `https://qarfash-api.onrender.com`) وضعه في:
   - متغير `SELF_URL` (لتفعيل الـ Self-Ping).
   - داخل ملف `index.html` في المتغير `API_BASE`.

## متغيرات البيئة المطلوبة (Environment Variables)

| المتغير | إلزامي | الوصف | مثال |
|---|---|---|---|
| `FIREBASE_DB_URL` | ✅ | رابط قاعدة بيانات Realtime Database (بدون شرطة في النهاية). | `https://qarfash-98772-default-rtdb.firebaseio.com` |
| `FIREBASE_DB_SECRET` | ⛔️ اختياري | السر القديم للوصول إلى DB إن كانت قواعد الأمان تتطلب مصادقة. | `xxxxxxxxxxxxxx` |
| `API_CLIENT_KEY` | ✅ | مفتاح سري مشترك بين التطبيق والسيرفر، يُرسل في هيدر `X-Client-Key`. | `qf-9f3b2d…` |
| `ALLOWED_ORIGINS` | ⛔️ | قائمة Origins مسموحة مفصولة بفواصل. ضع `*` للسماح للجميع (مناسب لـ WebView). | `*` |
| `SELF_URL` | ✅ | رابط خدمة Render نفسها — يُستخدم لمنع النوم (Spin-down). | `https://qarfash-api.onrender.com` |
| `PORT` | ⛔️ | يضبطه Render تلقائياً، لا تتدخل. | `10000` |

## نقاط الاتصال (Endpoints)

| Method | Path | الوصف |
|---|---|---|
| GET | `/` | فحص بسيط (نص). |
| GET | `/health` | حالة الخدمة JSON. |
| GET | `/ping` | يعيد `pong` (يستخدمه الـ keep-alive). |
| GET | `/api/data` | جميع الأناشيد مرتبة حسب الأحدث. **يتطلب `X-Client-Key`**. |
| GET | `/api/data/:id` | نشيد واحد. **يتطلب `X-Client-Key`**. |

## استخدام الواجهة

ضع ملف `public/index.html` في مجلد Assets داخل Sketchware ثم حمّله في WebView.
عدّل في أعلى الملف:

```js
const API_BASE = 'https://qarfash-api.onrender.com';
const CLIENT_KEY = 'نفس قيمة API_CLIENT_KEY';
```
