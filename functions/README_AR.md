# بوابة Archive Admin على Firebase Functions

هذه الخدمة هي مسار الكتابة الآمن لتطبيق Archive Admin. تقرأ المحتوى من Firebase Realtime Database، وتنفّذ عمليات المنشورات والأقسام والقوائم والأناشيد، وتصدر توقيع Cloudinary قصير العمر لرفع الصور وملفات PDF والفيديو والصوت. لا يُضمّن أي مفتاح Firebase Admin أو Cloudinary secret داخل APK.

## المتغيرات المطلوبة

يجب ضبط المتغيرات التالية في بيئة Functions فقط، خارج GitHub:

`FIREBASE_DB_URL` و`ADMIN_USERNAME` و`ADMIN_PASSWORD_HASH` و`CLOUDINARY_CLOUD_NAME` و`CLOUDINARY_API_KEY` و`CLOUDINARY_API_SECRET` و`JWT_ACCESS_SECRET`.

## النشر

يتطلب النشر حساب Firebase يملك صلاحية تفعيل Cloud Functions وCloud Build وArtifact Registry، بالإضافة إلى مشروع Firebase على خطة تدعم Cloud Functions. بعد النشر يُحقن عنوان HTTPS الخاص بالدالة في `CAPACITOR_ADMIN_API_URL` عند بناء APK Admin.

## ملاحظة أمنية

قواعد RTDB العامة في المستودع مقصود بها منع الكتابة العامة فقط. يجب مراجعة القواعد في Firebase Console قبل النشر النهائي، وتدوير مفاتيح Firebase Admin وCloudinary وJWT إذا تم كشفها خارج بيئة الخادم.
