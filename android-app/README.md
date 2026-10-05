# SUBMARINE Android

Package ID: `asia.submarine.app`
App name: `SUBMARINE`
Production URL: `https://submarine.asia/`

This is the Android Trusted Web Activity (TWA) wrapper for the existing SUBMARINE PWA.

## Trust verification

A TWA becomes browser-chrome-free only after Digital Asset Links verifies that the Android app and `submarine.asia` belong to the same owner.

The site must publish:

`https://submarine.asia/.well-known/assetlinks.json`

The final SHA-256 fingerprint for that file must be the Google Play **app signing certificate** fingerprint used on installed production builds. When Play App Signing is enabled, do not substitute the upload-key fingerprint for the Play app-signing fingerprint.

## Build artifacts

GitHub Actions builds:
- release AAB
- debug APK

Release signing is enabled when these repository secrets are available:
- `ANDROID_KEYSTORE_BASE64`
- `ANDROID_KEYSTORE_PASSWORD`
- `ANDROID_KEY_ALIAS`
- `ANDROID_KEY_PASSWORD`
