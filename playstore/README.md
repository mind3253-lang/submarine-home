# SUBMARINE Android / Google Play

Package ID: `asia.submarine.app`
App name: `SUBMARINE`
Production URL: `https://submarine.asia/`
Privacy policy: `https://submarine.asia/privacy.html`

## Architecture

Android is packaged as a Trusted Web Activity (TWA) around the existing SUBMARINE PWA.
Source project: `android-app/`
GitHub Actions workflow: `.github/workflows/android-build.yml`

The Android build targets API level 36.

## Build outputs

Each successful build produces:
- release Android App Bundle (AAB)
- debug APK

When these repository secrets exist, the release AAB is signed automatically:
- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`

Never commit the keystore or passwords to the repository.

## Digital Asset Links

For the production TWA, publish:

`https://submarine.asia/.well-known/assetlinks.json`

Use the SHA-256 fingerprint of the **Google Play app signing certificate** shown in Play Console after Play App Signing is configured. The upload-key fingerprint is not a substitute when Google Play signs installed builds.

## Store listing source

See `playstore/metadata.json`.
