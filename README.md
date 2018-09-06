# PHP Crypt

[![Tests](https://github.com/philiprehberger/php-crypt/actions/workflows/tests.yml/badge.svg)](https://github.com/philiprehberger/php-crypt/actions/workflows/tests.yml)
[![Latest Version on Packagist](https://img.shields.io/packagist/v/philiprehberger/php-crypt.svg)](https://packagist.org/packages/philiprehberger/php-crypt)
[![License](https://img.shields.io/github/license/philiprehberger/php-crypt)](LICENSE)

Secure-by-default encryption with AES-256-GCM and key rotation.

---

## Requirements

| Dependency | Version |
|------------|---------|
| PHP        | ^8.2    |
| ext-openssl | *      |

---

## Installation

```bash
composer require philiprehberger/php-crypt
```

---

## Usage

### Basic Encryption

```php
use PhilipRehberger\Crypt\Crypt;

$key = Crypt::generateKey();

$encrypted = Crypt::encrypt('sensitive data', $key);
$decrypted = Crypt::decrypt($encrypted, $key);
```

### Additional Authenticated Data (AAD)

Bind ciphertext to a context so it cannot be used elsewhere:

```php
$encrypted = Crypt::encrypt('data', $key, aad: 'user:42');
$decrypted = Crypt::decrypt($encrypted, $key, aad: 'user:42');
```

### Key Rotation

Re-encrypt data when rotating keys:

```php
$rotated = Crypt::rotate($encrypted, $oldKey, $newKey);
```

### Array Encryption

Encrypt and decrypt arrays (serialized as JSON):

```php
$encrypted = Crypt::encryptArray(['name' => 'Alice', 'role' => 'admin'], $key);
$data = Crypt::decryptArray($encrypted, $key);
```

### KeyChain (Multi-Key Management)

Manage key rotation transparently — encrypts with the current key, decrypts with any known key:

```php
use PhilipRehberger\Crypt\KeyChain;

$chain = new KeyChain($newKey, $oldKey1, $oldKey2);

$encrypted = $chain->encrypt('data');
$decrypted = $chain->decrypt($encryptedWithAnyKey);

// Re-encrypt all ciphertexts with the current key
$rotated = $chain->rotateAll($ciphertexts);
```

---

## API

### `Crypt` (Static)

| Method | Description |
|--------|-------------|
| `generateKey(): string` | Generate a random base64-encoded 32-byte key |
| `encrypt(string $data, string $key, ?string $aad = null): string` | Encrypt data with AES-256-GCM |
| `decrypt(string $encrypted, string $key, ?string $aad = null): string` | Decrypt AES-256-GCM ciphertext |
| `rotate(string $encrypted, string $oldKey, string $newKey): string` | Re-encrypt data with a new key |
| `encryptArray(array $data, string $key): string` | Encrypt an array as JSON |
| `decryptArray(string $encrypted, string $key): array` | Decrypt a JSON-encoded array |

### `KeyChain`

| Method | Description |
|--------|-------------|
| `__construct(string $currentKey, string ...$previousKeys)` | Create a key chain |
| `encrypt(string $data): string` | Encrypt with the current key |
| `decrypt(string $encrypted): string` | Decrypt with any key in the chain |
| `rotateAll(array $ciphertexts): array` | Re-encrypt all ciphertexts with the current key |

### Exceptions

| Exception | When |
|-----------|------|
| `InvalidKeyException` | Key is not a valid base64-encoded 32-byte string |
| `DecryptionException` | Decryption fails (wrong key, tampered data, invalid ciphertext) |

---

## Development

```bash
composer install
vendor/bin/phpunit
vendor/bin/pint --test
vendor/bin/phpstan analyse
```

## License

MIT
