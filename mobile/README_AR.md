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

## الهوية وتجربة الوسائط

تم تحديث User وAdmin بهوية Archive جديدة تعتمد العاجي والفحمي والكوبالت، مع علامة كتاب/أرشيف/تشغيل، وأيقونة Android تكيفية، وشاشة بداية جديدة. في User تظهر بطاقة المكتبة والعداد والبحث، وفي Admin تظهر بطاقة `مركز المحتوى` وأزرار سريعة لإنشاء منشور أو قسم أو قائمة.

تستخدم المنشورات والأقسام والقوائم نفس نموذج الوسائط في Admin. يمكن رفع صورة أو PDF أو فيديو أو ملف صوتي، أو لصق رابط https، ثم رؤية العنصر داخل قائمة مرتبة قبل الحفظ. يتولى `media-tools.js` المشترك كشف النوع وتطبيع الروابط وتحويل روابط Archive.org وYouTube وVimeo وغيرها إلى صيغ عرض مدمجة عند الحاجة. فشل الرفع يعرض الآن السبب المعروف بدل رسالة عامة فقط.

## الأذونات

الأذونات المضافة يدويًا في Admin هي `INTERNET` فقط. User يضيف أذونات التشغيل الخلفي والإشعار لأن الصوت يعمل عند مغادرة التطبيق. يعتمد اختيار ملف PDF أو صورة أو فيديو على منتقي الملفات/النظام، لذلك لم تُضَف صلاحيات تخزين واسعة. يضيف Capacitor إذنًا داخليًا لحماية مستقبلات التطبيق، وهو ليس صلاحية تخزين أو موقع.

## الحدود الأمنية والتشغيلية

الـ APK يحتوي الواجهة المحلية والأيقونة وشاشة البداية فقط. لا يحتوي على Firebase secrets أو Cloudinary secret أو JWT secrets أو Hash كلمة مرور المدير. عند تشغيل Admin بعنوان API محمي، اكتب عنوان الخدمة في شاشة الدخول واضغط «حفظ وتجربة»؛ يُحفظ العنوان محليًا في WebView ولا يُضمّن أي سر داخل التطبيق. لكي تعمل القراءة والرفع والحفظ، يجب أن تكون الخدمة قابلة للوصول من الهاتف.

تطبيق User لا يحتوي `admin.html` أو `admin-login.html`، وتطبيق Admin لا يضم واجهة User كواجهة تشغيل. في وضع Firebase المباشر، تُقرأ بيانات User وAdmin من Realtime Database دون Render، بينما تبقى الكتابة الإدارية والرفع بحاجة إلى Backend محمي أو Firebase Functions.

## Firebase Functions للكتابة الآمنة

أضيفت خدمة `functions/index.js` لتكون بوابة Admin الآمنة خارج APK. توفر تسجيل الدخول، CRUD للمنشورات والأقسام والقوائم والأناشيد، وتوقيع Cloudinary قصير العمر لرفع الصور وPDF والفيديو والصوت. استخدمها بعد نشرها عبر Firebase ثم ابنِ Admin مثل المثال التالي:

```bash
CAPACITOR_FIREBASE_DB_URL="https://PROJECT-default-rtdb.firebaseio.com" \\
CAPACITOR_ADMIN_API_URL="https://us-central1-PROJECT.cloudfunctions.net/archiveAdmin" \\
./mobile/build-debug.sh
```

يتطلب النشر صلاحيات Google Cloud لتفعيل Cloud Functions وCloud Build وArtifact Registry، بالإضافة إلى خطة Firebase مناسبة. الحساب المستخدم في محاولة النشر الحالية أعاد 403 عند تفعيل الخدمات؛ لذلك بقيت APKات الحالية في وضع Firebase المباشر للقراءة الآمنة، ولم أفتح الكتابة العامة في قاعدة البيانات.

## الصوت والروابط

يدعم APK User تشغيل الصوت عبر Native Audio في Android مع خدمة أمامية وإشعار دائم أثناء التشغيل. عند أول تشغيل على Android 13 أو أحدث، سيطلب التطبيق صلاحية الإشعارات، وهي مطلوبة لظهور إشعار التشغيل. أضيفت كذلك صلاحيات foreground media playback وWAKE_LOCK المطلوبة لاستمرار الصوت عند مغادرة التطبيق، ولم تُضف صلاحيات تخزين عامة.

تُفتح الروابط الخارجية مثل Archive.org وYouTube وVimeo عبر سطح Browser مناسب لـ Android بدل الاعتماد على `target=_blank` داخل WebView. وتظل روابط PDF والوسائط المباشرة قابلة للفتح من الرابط الأصلي أو عبر بروكسي Archive عندما تتطلب Range أو معالجة خاصة.

## الاختبارات

نجح فحص JavaScript المضمّن، وفحص `media-tools.js`، و`npm test`، ومزامنة Capacitor، وبناء Gradle للنسختين، وفحص توقيع Debug. لا يوجد جهاز Android فعلي أو Emulator متصل في بيئة البناء، لذلك يحتاج إشعار الصوت والفتح الميداني للملفات إلى تحقق نهائي على هاتف Android.
