# Archive Android — User وAdmin

يحتوي هذا المجلد على غلافين مستقلين عبر Capacitor:

| الغلاف | المعرف | المحتوى |
|---|---|---|
| Archive User | `com.archive.user` | واجهة المستخدم وApp Shell والوسائط العامة فقط. |
| Archive Admin | `com.archive.admin` | صفحة دخول المدير ولوحة الإدارة فقط. |

## البناء

من جذر المستودع، يمكن بناء User بقراءة Firebase المباشرة، بينما يحتاج Admin إلى عنوان Backend محمي لعمليات الإدارة:

```bash
export CAPACITOR_FIREBASE_DB_URL=https://YOUR_PROJECT-default-rtdb.firebaseio.com
export CAPACITOR_ADMIN_API_URL=https://YOUR_PROTECTED_ADMIN_API
export CAPACITOR_USER_API_URL=
node mobile/prepare-mobile-webdirs.js
(cd mobile/archive-user && npx cap sync android)
(cd mobile/archive-admin && npx cap sync android)

export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"

(cd mobile/archive-user/android && ./gradlew assembleDebug)
(cd mobile/archive-admin/android && ./gradlew assembleDebug)
```

تظهر النتائج في `android/app/build/outputs/apk/debug/app-debug.apk` لكل غلاف. أو استخدم الأمر الموحد:

```bash
CAPACITOR_FIREBASE_DB_URL=https://YOUR_PROJECT-default-rtdb.firebaseio.com \\
CAPACITOR_ADMIN_API_URL=https://YOUR_PROTECTED_ADMIN_API \\
npm run android:debug
```

يقبل سكربت البناء `CAPACITOR_FIREBASE_DB_URL` لنسخة User، ويستخدم `CAPACITOR_ADMIN_API_URL` لنسخة Admin. لا يضع أي Firebase Admin secret داخل أي APK.

## الأذونات

الأذونات المضافة يدويًا في Admin هي `INTERNET` فقط. User يضيف أذونات التشغيل الخلفي والإشعار لأن الصوت يعمل عند مغادرة التطبيق. يعتمد اختيار ملف PDF أو صورة أو فيديو على منتقي الملفات/النظام، لذلك لم تُضَف صلاحيات تخزين واسعة. يضيف Capacitor إذنًا داخليًا لحماية مستقبلات التطبيق، وهو ليس صلاحية تخزين أو موقع.

## الحدود الأمنية والتشغيلية

الـ APK يحتوي الواجهة المحلية والأيقونة وشاشة البداية فقط. لا يحتوي على Firebase secrets أو Cloudinary secret أو JWT secrets أو Hash كلمة مرور المدير. عند فتح Admin لأول مرة، اكتب عنوان خادم Archive في خانة «عنوان خادم API» داخل شاشة الدخول واضغط «حفظ وتجربة»؛ يُحفظ العنوان محليًا في WebView ولا يُضمّن في Git أو كسر داخل التطبيق. لكي تجلب النسخة بيانات Firebase وتنفذ الرفع والقراءة الآمنة للروابط، يجب أن يكون الخادم قابلًا للوصول من الهاتف. استخدم HTTPS للخادم المنشور، أو `http://10.0.2.2:PORT` مع Android Emulator، أو عنوان LAN محليًا في اختبار Debug.

تطبيق User لا يحتوي `admin.html` أو `admin-login.html`، وتطبيق Admin لا يضم واجهة User كواجهة تشغيل. في وضع Firebase المباشر، تُقرأ بيانات User من Realtime Database دون Render، بينما تبقى الكتابة الإدارية والرفع بحاجة إلى Backend محمي أو Firebase Functions.

## صيانة الإصدار الأخير

يفتح APK Admin الآن `admin.html` مباشرة عند التشغيل بدل عرض صفحة الدخول أولًا. إذا لم توجد جلسة Admin محفوظة أو انتهت الجلسة، يعيد التطبيق التوجيه إلى `admin-login.html`؛ لا يمكن إزالة حماية API بالكامل لأن ذلك سيجعل كل من يملك APK قادرًا على تعديل البيانات. بعد تسجيل الدخول مرة واحدة، يفتح التطبيق لوحة الإدارة مباشرة في التشغيلات التالية.

يدعم APK User تشغيل الصوت عبر Native Audio في Android مع خدمة أمامية وإشعار دائم أثناء التشغيل. عند أول تشغيل على Android 13 أو أحدث، سيطلب التطبيق صلاحية الإشعارات، وهي مطلوبة لظهور إشعار التشغيل. أضيفت كذلك صلاحيات foreground media playback وWAKE_LOCK المطلوبة لاستمرار الصوت عند مغادرة التطبيق، ولم تُضف صلاحيات تخزين عامة.

تُفتح الروابط الخارجية مثل Archive.org وYouTube وVimeo عبر سطح Browser مناسب لـ Android بدل الاعتماد على `target=_blank` داخل WebView. وتظل روابط الوسائط المباشرة تمر عبر بروكسي Archive عندما تكون بحاجة إلى اكتشاف النوع أو Range/PDF.

## الاتصال المباشر بـ Firebase

يستطيع APK User قراءة `posts` و`sections` و`sideMenu` و`anasheed` و`appConfig` و`appStatus` مباشرة من Firebase Realtime Database باستخدام رابط قاعدة البيانات العام فقط، ولا يضع `FIREBASE_DB_SECRET` أو ملف Firebase Admin SDK داخل APK. كما تفتح الوسائط العامة من روابطها الأصلية عند الحاجة.

نسخة Admin لا تُحوّل إلى كتابة مباشرة باستخدام Firebase Admin secret؛ ذلك سيكشف صلاحيات حذف وتعديل كاملة داخل APK. لذلك تحتاج عمليات الإدارة والرفع إلى Backend محمي أو Firebase Functions مع مصادقة مناسبة. يمكن بناء User بلا Render عبر `CAPACITOR_FIREBASE_DB_URL`، بينما يُمرّر `CAPACITOR_API_URL` إلى Admin فقط إذا كان مطلوبًا تشغيل الإدارة.
