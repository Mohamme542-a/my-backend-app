#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"

cd "$ROOT"
node mobile/prepare-mobile-webdirs.js
for app in archive-user archive-admin; do
  (cd "mobile/$app" && npx cap sync android)
  (cd "mobile/$app/android" && chmod +x ./gradlew && ./gradlew assembleDebug --no-daemon)
done

mkdir -p "$ROOT/artifacts"
cp "$ROOT/mobile/archive-user/android/app/build/outputs/apk/debug/app-debug.apk" "$ROOT/artifacts/Archive-User-debug.apk"
cp "$ROOT/mobile/archive-admin/android/app/build/outputs/apk/debug/app-debug.apk" "$ROOT/artifacts/Archive-Admin-debug.apk"
printf 'APKs written to %s/artifacts\n' "$ROOT"
