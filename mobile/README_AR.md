# Archive Android — User وAdmin

يحتوي هذا المجلد على غلافين مستقلين عبر Capacitor:

| الغلاف | المعرف | المحتوى |
|---|---|---|
| Archive User | `com.archive.user` | واجهة المستخدم وApp Shell والوسائط العامة فقط. |
| Archive Admin | `com.archive.admin` | صفحة دخول المدير ولوحة الإدارة فقط. |

## البناء

من جذر المستودع:

```bash
node mobile/prepare-mobile-webdirs.js
(cd mobile/archive-user && npx cap sync android)
(cd mobile/archive-admin && npx cap sync android)

export ANDROID_HOME="$HOME/Android/Sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"

(cd mobile/archive-user/android && ./gradlew assembleDebug)
(cd mobile/archive-admin/android && ./gradlew assembleDebug)
```

تظهر النتائج في `android/app/build/outputs/apk/debug/app-debug.apk` لكل غلاف.

## الأذونات

الأذونات المضافة يدويًا هي `INTERNET` فقط. يعتمد اختيار ملف PDF أو صورة أو فيديو على منتقي الملفات/النظام، لذلك لم تُضَف صلاحيات تخزين واسعة. يضيف Capacitor إذنًا داخليًا لحماية مستقبلات التطبيق، وهو ليس صلاحية تخزين أو موقع.

## الحدود الأمنية والتشغيلية

الـ APK يحتوي الواجهة المحلية والأيقونة وشاشة البداية فقط. لا يحتوي على Firebase secrets أو Cloudinary secret أو JWT secrets أو Hash كلمة مرور المدير. لكي تجلب النسخة بيانات Firebase وتنفذ الرفع والقراءة الآمنة للروابط، يجب أن يكون الخادم المنشور قابلًا للوصول من التطبيق عبر إعداد بيئة البناء/التوزيع. لم أضع عنوانًا افتراضيًا أو سرًا داخل APK بدل اختلاق رابط غير معروف.

تطبيق User لا يحتوي `admin.html` أو `admin-login.html`، وتطبيق Admin لا يضم واجهة User كواجهة تشغيل.
