# openpgp-ktx

Reimplementation of [OpenKeychain]'s integration library [openpgp-api]. Written entirely in Kotlin,
it leverages Jetpack to be compatible with modern apps, unlike the original library.

Password Store uses it to delegate PGP operations to OpenKeychain when the "Use OpenKeychain"
setting is enabled, which is what makes hardware tokens such as YubiKeys usable with the app.

[OpenKeychain]: https://github.com/open-keychain/open-keychain
[openpgp-api]: https://github.com/open-keychain/openpgp-api
