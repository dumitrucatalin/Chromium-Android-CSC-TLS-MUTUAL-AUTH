# A Chromium Android V65.0.3325.230 with Conscypt Provider for mutual TLS Auth using remote Cloud Signature Consortium signing

### Introduction
- This is the source code of Chromium Android modified for enabling client TLS Authentication using Cloud Signature Consortium remote signing .
- All Chromium origilally files are from the [Chromium project](https://github.com/kuoruan/Chromium-Android/ "Chromium source repo").
- As Cryptographic provider is used [Conscrypt-for-CSC-TLS-MUTUAL-AUTH](https://bitbucket.org/catalindumitru96/conscrypt-for-csc-tls-mutual-auth/src/master/ "Conscypt custom source repo") , a custom implementation of [open source Conscypt project](https://github.com/google/conscrypt "Conscypt source repo"). 
- For remote signing process was used [Cloud Signature Consortium, Specificationsfor Remote Signature applications v0.1.7.9](https://cloudsignatureconsortium.org/wp-content/uploads/2020/05/CSC_API_V0_0.1.7.9.pdf "Cloud Signature Consortium").
- You can also build your own Android browser with this repository, the steps for building are the same with [Chromium project](https://github.com/kuoruan/Chromium-Android/ "Chromium source repo").

### Start Working
- You can also build your own Android browser with this repository, the steps for building are the same with [Chromium project](https://github.com/kuoruan/Chromium-Android/ "Chromium source repo").
- For TLS remote signing you need to modify the app\src\main\res\raw\remote_signing_json_config.json file with your credentials, server, and redirect uri.
- The redirect uri need to be modified in AndroidManifest as well.
- The cloud server used for remote signing is [Trans Sped test platfom](https://cloudsignature.transsped.ro "Transsped")

### Copyright & License
Please see [LICENSE](https://chromium.googlesource.com/chromium/src/+/master/LICENSE).
#