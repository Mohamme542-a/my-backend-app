# ملاحظات بناء Android عبر Capacitor

## المصادر الرسمية

- Capacitor Android Documentation: https://capacitorjs.com/docs/android
- Capacitor Workflow: https://capacitorjs.com/docs/basics/workflow
- Android CLI Download: https://developer.android.com/tools/agents/android-cli/download

## متطلبات اعتمدت عليها

توثيق Capacitor الحالي يوضح أن حزمة Android تُضاف عبر `@capacitor/android` ثم `npx cap add android`، وأن مزامنة أصول الويب تتم عبر `npx cap sync`، ويمكن بناء APK عبر مشروع Android الناتج. يدعم Capacitor Android API 24 وما بعده، ويستخدم Android System WebView على Android 10 وما بعده.

صفحة Android الرسمية الحالية توفر أداة CLI لنظام Linux عبر مثبت المستخدم:

```bash
curl -fsSL https://dl.google.com/android/cli/latest/linux_x86_64/install.sh | bash
```

سيتم استخدام هذه الأدوات فقط لبناء Debug محلي، ولن تُضمّن أسرار الخادم داخل أي حزمة Android.
