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


## Google Play launch checklist

Prepared before Play Console identity verification completes:

- [x] Package ID fixed: `asia.submarine.app`
- [x] Target SDK 36
- [x] Release AAB build succeeds
- [x] Store metadata prepared
- [x] Privacy policy published
- [x] TWA Digital Asset Links template prepared
- [x] Play Console app-content/data-safety basis documented
- [ ] Create app in Play Console after account verification
- [ ] Enable Play App Signing and obtain app-signing SHA-256 certificate fingerprint
- [ ] Publish `/.well-known/assetlinks.json` with Play app-signing fingerprint
- [ ] Create/secure upload keystore and configure GitHub Actions secrets
- [ ] Build signed release AAB
- [ ] Upload signed AAB to Play Console
- [ ] Reuse approved iOS store artwork/screenshots where Google Play dimensions permit
- [ ] Complete app access, ads, target audience, content rating and data safety forms
- [ ] Complete required testing track for this developer account, if Play Console requires it
- [ ] Submit production release
