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

الواجهة والأصول محلية داخل APK. يحتوي User على Firebase DB URL العام للقراءة المباشرة فقط، بينما يحتاج Admin إلى عنوان خدمة إدارة محمية عند تفعيل الكتابة والرفع. لا توجد أسرار أو بيانات دخول ثابتة داخل APK. يمكن إعداد عنوان الخدمة وقت البناء عبر `CAPACITOR_ADMIN_API_URL`، ولا يُنصح بفتح الكتابة العامة في Firebase.

## مراجع تقنية

- [Capacitor Android Documentation](https://capacitorjs.com/docs/android)
- [Capacitor Workflow](https://capacitorjs.com/docs/basics/workflow)
- [Android CLI Download](https://developer.android.com/tools/agents/android-cli/download)

## هوية Archive الجديدة وتجربة الاستوديو

أعيد تصميم User وAdmin بواجهة تحريرية موحّدة تعتمد العاجي والفحمي والكوبالت الهادئ، مع علامة Archive الجديدة المكوّنة من كتاب وصندوق أرشيف ورمز تشغيل. استُبدلت موارد الأيقونة التكيفية وصور شاشة البداية في الغلافين، وأضيفت بطاقة مكتبة User وبطاقة `مركز المحتوى` في Admin مع مسارات سريعة للمنشور والقسم والقائمة. أضيف `media-tools.js` كمكوّن مشترك لتطبيع روابط https وكشف أنواع PDF والصوت والفيديو والصور وتحويل روابط Archive.org والمنصات إلى صيغ embed.

أضيف Native Audio لنسخة User مع خدمة Android أمامية وإشعار تشغيل، وطلب صلاحية الإشعارات على Android 13+، وصلاحيات `FOREGROUND_SERVICE` و`FOREGROUND_SERVICE_MEDIA_PLAYBACK` و`WAKE_LOCK`. أضيف Browser لفتح الروابط الخارجية من Android. لا تحتاج نسخة Admin إلى أذونات الصوت أو الإشعارات.

التحقق الأخير: نجح فحص JavaScript المضمّن، و`npm test`، ومزامنة Capacitor، وبناء User وAdmin عبر Gradle، وتوقيع APK. يحتوي User على أذونات الإنترنت والتشغيل الخلفي والإشعار فقط، بينما يحتوي Admin على الإنترنت فقط. لم يتم اختبار الإشعار على جهاز Android فعلي لعدم وجود جهاز متصل ببيئة البناء؛ يحتاج التحقق النهائي على الهاتف إلى تشغيل أنشودة ثم إغلاق التطبيق والتأكد من ظهور إشعار Archive.

## وضع Firebase المباشر وخدمة Admin الآمنة

في آخر بناء، حُقن `FIREBASE_DB_URL` العام فقط داخل User وAdmin، وأصبح User يقرأ المنشورات والأقسام والقائمة والأناشيد والإعدادات مباشرة من Realtime Database دون عنوان Render. كما يستطيع Admin قراءة الإحصاءات والمواد القديمة مباشرة ويفتح دون شاشة دخول في هذا الوضع.

عمليات Admin التي تغيّر البيانات أو ترفع ملفات تبقى مرفوضة في وضع الاتصال المباشر read-only؛ لا يجوز وضع `FIREBASE_DB_SECRET` أو Firebase Admin SDK داخل APK، لأن ذلك يمنح كل من يستخرج التطبيق صلاحيات حذف وتعديل كاملة. أضيفت الآن خدمة `functions/index.js` كـ Firebase Functions محمية توفر تسجيل دخول Admin، CRUD للمنشورات والأقسام والقوائم والأناشيد، وتوقيع Cloudinary للصور وPDF والفيديو والصوت. النشر الفعلي لم يكتمل لأن حساب Firebase الحالي أعاد 403 عند محاولة تفعيل Cloud Functions وCloud Build.

نتائج البناء الجديد: User وAdmin تضمنا الهوية الجديدة، شاشة البداية الجديدة، `media-tools.js`، وموارد الأيقونة الجديدة، ونجح توقيع Debug. لا يحتوي أي منهما على Firebase Admin SDK أو Cloudinary secret. User يعمل بقراءة Firebase المباشرة، وAdmin يعمل بقراءة Firebase المباشرة مع تنبيه صريح بأن الكتابة تحتاج بوابة Functions.
