# SUBMARINE Android / Google Play

Package ID: `asia.submarine.app`
App name: `SUBMARINE`
Production URL: `https://submarine.asia`
Privacy policy: `https://submarine.asia/privacy.html`

## Build

The Android project is generated from the existing Capacitor wrapper in `ios-app/`.
GitHub Actions workflow: `.github/workflows/android-build.yml`.

Each build produces:
- release Android App Bundle (AAB)
- debug APK

When these repository secrets exist, the release AAB is signed automatically:
- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

Never commit the keystore or passwords to the repository.

## Store listing source

See `playstore/metadata.json`.
