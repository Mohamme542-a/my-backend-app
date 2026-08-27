#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$ANDROID_HOME}"
export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"

cd "$ROOT"
if [[ -z "${CAPACITOR_ADMIN_API_URL:-${CAPACITOR_API_URL:-}}" && -z "${CAPACITOR_FIREBASE_DB_URL:-}" ]]; then
  echo "Set CAPACITOR_FIREBASE_DB_URL for User direct reads, or CAPACITOR_ADMIN_API_URL for the protected Admin API." >&2
  exit 2
fi
if [[ -z "${CAPACITOR_ADMIN_API_URL:-${CAPACITOR_API_URL:-}}" ]]; then
  echo "Warning: Admin APK will be built without an API origin; Firebase direct mode is read-only and cannot replace protected admin writes." >&2
fi
node mobile/prepare-mobile-webdirs.js
for app in archive-user archive-admin; do
  (cd "mobile/$app" && npx cap sync android)
  (cd "mobile/$app/android" && chmod +x ./gradlew && ./gradlew assembleDebug --no-daemon)
done

mkdir -p "$ROOT/artifacts"
cp "$ROOT/mobile/archive-user/android/app/build/outputs/apk/debug/app-debug.apk" "$ROOT/artifacts/Archive-User-debug.apk"
cp "$ROOT/mobile/archive-admin/android/app/build/outputs/apk/debug/app-debug.apk" "$ROOT/artifacts/Archive-Admin-debug.apk"
printf 'APKs written to %s/artifacts\n' "$ROOT"
