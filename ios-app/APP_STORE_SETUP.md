# App Store setup

App: SUBMARINE
Bundle ID: asia.submarine.app
Production URL: https://submarine.asia

## Automated now
GitHub Actions generates the Capacitor iOS native project on a macOS runner and verifies that the app compiles as an unsigned simulator build.

## Required later for App Store upload
Apple distribution signing credentials and an App Store Connect API key (or equivalent authorized signing/upload setup) must be provided securely. Never commit private keys, certificates, API keys, or passwords to this repository.
