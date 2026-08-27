# تقرير بناء Archive Android Debug

## النتائج

تم بناء تطبيقين مستقلين عبر Capacitor 8.5.0 وAndroid SDK Platform 36:

| التطبيق | package ID | label | النتيجة |
|---|---|---|---|
| Archive User | `com.archive.user` | Archive | APK Debug ناجح وموقّع بتوقيع Debug عبر APK Signature Scheme v2. |
| Archive Admin | `com.archive.admin` | Archive Admin | APK Debug ناجح وموقّع بتوقيع Debug عبر APK Signature Scheme v2. |

## الأذونات

يحتوي كل APK على `android.permission.INTERNET` فقط كإذن تطبيقي مطلوب للوصول إلى API والوسائط. لم تُضَف صلاحيات تخزين أو موقع أو جهات اتصال أو إشعارات. الإذن الداخلي الخاص بـ Capacitor لحماية المستقبلات ليس صلاحية مستخدم واسعة.

## الفصل

نسخة User تشحن `index.html` وService Worker مخصصًا للمستخدم فقط، ولا تشحن `admin.html` أو `admin-login.html`. نسخة Admin تشحن صفحة الدخول ولوحة الإدارة فقط. لكل نسخة package ID مستقل وأيقونة واسم Android مستقل.

## الأمان

تم فحص محتوى HTML وService Worker داخل APK بحثًا عن `JWT_ACCESS_SECRET` و`JWT_REFRESH_SECRET` و`CSRF_SECRET` و`COOKIE_SECRET` و`FIREBASE_AUTH_TOKEN` و`CLOUDINARY_API_SECRET` و`ADMIN_PASSWORD_HASH` والمفتاح القديم لخدمة الرفع، ولم تُعثر على هذه القيم. كما أزيلت القيم الثابتة القديمة من `.env.example` واستُبدلت بـ placeholders.

## إصلاح اتصال WebView بالـ API

كانت المشكلة أن صفحة Admin تستخدم `location.origin` وطلبات نسبية؛ داخل Capacitor هذا يعني أصل WebView المحلي `https://localhost` وليس خادم Archive. تم إصلاح ذلك بإضافة `api-config.js` مع عنوان قابل للحفظ من شاشة الدخول، وتغيير الطلبات إلى عنوان API المطلق، وإضافة `admin-login.html` إلى حزمة Admin حتى يعمل الرجوع بعد انتهاء الجلسة. كما سُمح لأصل Capacitor المعروف `https://localhost` في CORS فقط، وضُبطت كوكيّات CSRF والتجديد إلى `SameSite=None; Secure` لهذا الأصل مع إبقاء سياسة المتصفح العادي أكثر تشددًا.

داخل APK Admin يكتب المدير عنوان خادم Archive في خانة «عنوان خادم API» ثم يضغط «حفظ وتجربة». لا يوجد عنوان مخترع أو سر ثابت داخل APK. في Android Emulator استخدم `http://10.0.2.2:PORT` للاختبار المحلي، وفي الاستخدام الحقيقي استخدم عنوان HTTPS المنشور.

## الاختبارات

نجح `npm test`، وفحص بنية JavaScript، و`git diff --check`، ومزامنة Capacitor، وبناء Gradle للنسختين، وفحص manifest وpackage IDs والأذونات وتوقيع APK. واختُبرت دورة Origin `https://localhost` محليًا: `/api/csrf` أعاد CORS وCSRF cookie، وتسجيل دخول تجريبي أعاد access token، ثم نجح `/api/admin/auth/me`. لم يكن هناك جهاز Android فعلي أو Emulator متصل داخل بيئة البناء، لذلك لم يُنفذ تثبيت ميداني؛ APKات الناتجة Debug وجاهزة للتثبيت على جهاز Android متوافق.

## نتيجة الاتصال الفعلي بالبيانات القديمة

تم اختبار الخادم المنشور `https://my-backend-app-ajry.onrender.com` بإعدادات البيئة المرفوعة. أعاد `/healthz` الحالة 200، وأعادت المسارات العامة 170 مادة، و6 منشورات، و11 قسمًا، و7 عناصر في القائمة الجانبية. وباستخدام JWT موقّع من إعداد الخادم، أعادت مسارات Admin الحالة 200 مع الإحصاءات و6 منشورات و11 قسمًا و170 أنشودة و7 عناصر قائمة وبيانات التطبيق الكاملة. هذا يؤكد أن البيانات القديمة موجودة وأن سبب المشكلة كان عنوان API داخل WebView وليس فقدان الملفات.

## ملاحظة التشغيل

الواجهة والأصول محلية داخل APK. تبقى Firebase وCloudinary ومعالجة الروابط والرفع في خادم Archive، ولا توجد أسرار أو بيانات دخول داخل APK. تحتوي APKات الحالية على عنوان `https://my-backend-app-ajry.onrender.com` الذي تم اختباره، وتبقى شاشة Admin قادرة على تغييره محليًا عند الحاجة. لا يُحفظ أي سر داخل APK.

## مراجع تقنية

- [Capacitor Android Documentation](https://capacitorjs.com/docs/android)
- [Capacitor Workflow](https://capacitorjs.com/docs/basics/workflow)
- [Android CLI Download](https://developer.android.com/tools/agents/android-cli/download)

## صيانة الإصدار الأسود والأبيض والصوت الخلفي

أعيدت ألوان واجهة User وAdmin ودخول الإدارة إلى نظام أبيض وأسود، واستُبدل شعار Archive الملون بنسخة أحادية مناسبة للأيقونة وشاشة البداية والأغلفة الافتراضية. كما أصبح APK Admin يبدأ من لوحة الإدارة مباشرة؛ تبقى حماية API فعالة، وإذا لم توجد جلسة محفوظة يعرض التطبيق شاشة الدخول تلقائيًا، ثم يحفظ جلسة الدخول محليًا للتشغيلات التالية.

أضيف Native Audio لنسخة User مع خدمة Android أمامية وإشعار تشغيل، وطلب صلاحية الإشعارات على Android 13+، وصلاحيات `FOREGROUND_SERVICE` و`FOREGROUND_SERVICE_MEDIA_PLAYBACK` و`WAKE_LOCK`. أضيف Browser لفتح الروابط الخارجية من Android. لا تحتاج نسخة Admin إلى أذونات الصوت أو الإشعارات.

التحقق الأخير: نجح فحص JavaScript المضمّن، و`npm test`، ومزامنة Capacitor، وبناء User وAdmin عبر Gradle، وتوقيع APK. يحتوي User على أذونات الإنترنت والتشغيل الخلفي والإشعار فقط، بينما يحتوي Admin على الإنترنت فقط. لم يتم اختبار الإشعار على جهاز Android فعلي لعدم وجود جهاز متصل ببيئة البناء؛ يحتاج التحقق النهائي على الهاتف إلى تشغيل أنشودة ثم إغلاق التطبيق والتأكد من ظهور إشعار Archive.

## وضع Firebase المباشر بدون Render

في آخر بناء، حُقن `FIREBASE_DB_URL` العام فقط داخل User وAdmin، وأصبح User يقرأ المنشورات والأقسام والقائمة والأناشيد والإعدادات مباشرة من Realtime Database دون عنوان Render. كما يستطيع Admin قراءة الإحصاءات والمواد القديمة مباشرة ويفتح دون شاشة دخول في هذا الوضع.

عمليات Admin التي تغيّر البيانات أو ترفع ملفات بقيت مرفوضة في وضع الاتصال المباشر read-only؛ لا يجوز وضع `FIREBASE_DB_SECRET` أو Firebase Admin SDK داخل APK، لأن ذلك يمنح كل من يستخرج التطبيق صلاحيات حذف وتعديل كاملة. لتفعيل الكتابة مع إزالة Render، يلزم نشر API محمي كـ Firebase Functions أو خدمة Backend بديلة، ثم تمرير عنوانها في `CAPACITOR_ADMIN_API_URL` عند بناء Admin فقط.

نتائج البناء المباشر: User وAdmin بدون `onrender.com` داخل إعدادات APK، ونجح توقيع Debug. يحتوي User على اتصال Firebase العام، بينما لا يحتوي Admin على أي secret.
