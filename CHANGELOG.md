# Changelog

All notable changes to `php-crypt` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-03-16

### Changed
- Standardize composer.json: add type, homepage, scripts

## [1.0.1] - 2026-03-15

### Changed
- Standardize README badges

## [1.0.0] - 2026-03-15

### Added
- Initial release
- AES-256-GCM encryption and decryption via `Crypt` static API
- Key generation with `Crypt::generateKey()`
- Additional authenticated data (AAD) support
- Key rotation with `Crypt::rotate()`
- Array encryption/decryption with JSON serialization
- `KeyChain` for multi-key management and automatic fallback decryption
- `KeyChain::rotateAll()` for bulk re-encryption
- `DecryptionException` and `InvalidKeyException` for error handling
