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

## الاختبارات

نجح `npm test`، وفحص بنية JavaScript، و`git diff --check`، ومزامنة Capacitor، وبناء Gradle للنسختين، وفحص manifest وpackage IDs والأذونات وتوقيع APK. لم يكن هناك جهاز Android فعلي أو Emulator متصل داخل بيئة البناء، لذلك لم يُنفذ تثبيت ميداني؛ APKات الناتجة Debug وجاهزة للتثبيت على جهاز Android متوافق.

## ملاحظة التشغيل

الواجهة والأصول محلية داخل APK. تبقى Firebase وCloudinary ومعالجة الروابط والرفع في خادم Archive، ولا توجد أسرار أو بيانات دخول داخل APK. يجب ضبط عنوان الخادم في بيئة التوزيع قبل الاستخدام الكامل للبيانات الحية.

## مراجع تقنية

- [Capacitor Android Documentation](https://capacitorjs.com/docs/android)
- [Capacitor Workflow](https://capacitorjs.com/docs/basics/workflow)
- [Android CLI Download](https://developer.android.com/tools/agents/android-cli/download)
