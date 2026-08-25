# Archive Android — User وAdmin

يحتوي هذا المجلد على غلافين مستقلين عبر Capacitor:

| الغلاف | المعرف | المحتوى |
|---|---|---|
| Archive User | `com.archive.user` | واجهة المستخدم وApp Shell والوسائط العامة فقط. |
| Archive Admin | `com.archive.admin` | صفحة دخول المدير ولوحة الإدارة فقط. |

## البناء

من جذر المستودع، يجب تحديد عنوان خادم API قبل البناء:

```bash
export CAPACITOR_API_URL=https://my-backend-app-ajry.onrender.com
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
CAPACITOR_API_URL=https://my-backend-app-ajry.onrender.com npm run android:debug
```

يرفض سكربت البناء العمل إذا لم تُحدد `CAPACITOR_API_URL`، منعًا لإنتاج نسخة تشير إلى localhost داخل الهاتف.

## الأذونات

الأذونات المضافة يدويًا هي `INTERNET` فقط. يعتمد اختيار ملف PDF أو صورة أو فيديو على منتقي الملفات/النظام، لذلك لم تُضَف صلاحيات تخزين واسعة. يضيف Capacitor إذنًا داخليًا لحماية مستقبلات التطبيق، وهو ليس صلاحية تخزين أو موقع.

## الحدود الأمنية والتشغيلية

الـ APK يحتوي الواجهة المحلية والأيقونة وشاشة البداية فقط. لا يحتوي على Firebase secrets أو Cloudinary secret أو JWT secrets أو Hash كلمة مرور المدير. عند فتح Admin لأول مرة، اكتب عنوان خادم Archive في خانة «عنوان خادم API» داخل شاشة الدخول واضغط «حفظ وتجربة»؛ يُحفظ العنوان محليًا في WebView ولا يُضمّن في Git أو كسر داخل التطبيق. لكي تجلب النسخة بيانات Firebase وتنفذ الرفع والقراءة الآمنة للروابط، يجب أن يكون الخادم قابلًا للوصول من الهاتف. استخدم HTTPS للخادم المنشور، أو `http://10.0.2.2:PORT` مع Android Emulator، أو عنوان LAN محليًا في اختبار Debug.

تطبيق User لا يحتوي `admin.html` أو `admin-login.html`، وتطبيق Admin لا يضم واجهة User كواجهة تشغيل.

## صيانة الإصدار الأخير

يفتح APK Admin الآن `admin.html` مباشرة عند التشغيل بدل عرض صفحة الدخول أولًا. إذا لم توجد جلسة Admin محفوظة أو انتهت الجلسة، يعيد التطبيق التوجيه إلى `admin-login.html`؛ لا يمكن إزالة حماية API بالكامل لأن ذلك سيجعل كل من يملك APK قادرًا على تعديل البيانات. بعد تسجيل الدخول مرة واحدة، يفتح التطبيق لوحة الإدارة مباشرة في التشغيلات التالية.

يدعم APK User تشغيل الصوت عبر Native Audio في Android مع خدمة أمامية وإشعار دائم أثناء التشغيل. عند أول تشغيل على Android 13 أو أحدث، سيطلب التطبيق صلاحية الإشعارات، وهي مطلوبة لظهور إشعار التشغيل. أضيفت كذلك صلاحيات foreground media playback وWAKE_LOCK المطلوبة لاستمرار الصوت عند مغادرة التطبيق، ولم تُضف صلاحيات تخزين عامة.

تُفتح الروابط الخارجية مثل Archive.org وYouTube وVimeo عبر سطح Browser مناسب لـ Android بدل الاعتماد على `target=_blank` داخل WebView. وتظل روابط الوسائط المباشرة تمر عبر بروكسي Archive عندما تكون بحاجة إلى اكتشاف النوع أو Range/PDF.
