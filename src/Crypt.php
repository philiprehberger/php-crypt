<?php

declare(strict_types=1);

namespace PhilipRehberger\Crypt;

use PhilipRehberger\Crypt\Exceptions\DecryptionException;
use PhilipRehberger\Crypt\Exceptions\InvalidKeyException;

/**
 * Secure-by-default encryption using AES-256-GCM.
 *
 * All methods are static for convenient usage. Keys are 32-byte random values
 * encoded as base64 (44 characters). Ciphertext is stored as base64-encoded
 * concatenation of IV + tag + ciphertext.
 */
class Crypt
{
    private const CIPHER = 'aes-256-gcm';

    private const IV_LENGTH = 12;

    private const TAG_LENGTH = 16;

    private const KEY_LENGTH = 32;

    /**
     * Generate a new random encryption key.
     *
     * @return string Base64-encoded 32-byte key
     */
    public static function generateKey(): string
    {
        return base64_encode(random_bytes(self::KEY_LENGTH));
    }

    /**
     * Encrypt data using AES-256-GCM.
     *
     * @param  string  $data  Plaintext to encrypt
     * @param  string  $key  Base64-encoded 32-byte key
     * @param  string|null  $aad  Additional authenticated data
     * @return string Base64-encoded ciphertext (IV + tag + encrypted data)
     *
     * @throws InvalidKeyException If the key is invalid
     */
    public static function encrypt(string $data, string $key, ?string $aad = null): string
    {
        $decodedKey = self::validateKey($key);
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $data,
            self::CIPHER,
            $decodedKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad ?? '',
            self::TAG_LENGTH,
        );

        if ($ciphertext === false) {
            throw new \RuntimeException('Encryption failed: '.openssl_error_string());
        }

        return base64_encode($iv.$tag.$ciphertext);
    }

    /**
     * Decrypt data using AES-256-GCM.
     *
     * @param  string  $encrypted  Base64-encoded ciphertext
     * @param  string  $key  Base64-encoded 32-byte key
     * @param  string|null  $aad  Additional authenticated data
     * @return string Decrypted plaintext
     *
     * @throws InvalidKeyException If the key is invalid
     * @throws DecryptionException If decryption fails
     */
    public static function decrypt(string $encrypted, string $key, ?string $aad = null): string
    {
        $decodedKey = self::validateKey($key);
        $decoded = base64_decode($encrypted, true);

        if ($decoded === false) {
            throw new DecryptionException('Invalid base64 ciphertext.');
        }

        $minLength = self::IV_LENGTH + self::TAG_LENGTH;

        if (strlen($decoded) < $minLength) {
            throw new DecryptionException('Ciphertext is too short.');
        }

        $iv = substr($decoded, 0, self::IV_LENGTH);
        $tag = substr($decoded, self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($decoded, $minLength);

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $decodedKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad ?? '',
        );

        if ($plaintext === false) {
            throw new DecryptionException('Decryption failed. The key may be wrong or the data may be tampered with.');
        }

        return $plaintext;
    }

    /**
     * Re-encrypt data with a new key.
     *
     * @param  string  $encrypted  Base64-encoded ciphertext encrypted with the old key
     * @param  string  $oldKey  Base64-encoded old key
     * @param  string  $newKey  Base64-encoded new key
     * @return string Base64-encoded ciphertext encrypted with the new key
     *
     * @throws InvalidKeyException If either key is invalid
     * @throws DecryptionException If decryption with the old key fails
     */
    public static function rotate(string $encrypted, string $oldKey, string $newKey): string
    {
        $plaintext = self::decrypt($encrypted, $oldKey);

        return self::encrypt($plaintext, $newKey);
    }

    /**
     * Encrypt an array as JSON using AES-256-GCM.
     *
     * @param  array<mixed>  $data  Array to encrypt
     * @param  string  $key  Base64-encoded 32-byte key
     * @return string Base64-encoded ciphertext
     *
     * @throws InvalidKeyException If the key is invalid
     */
    public static function encryptArray(array $data, string $key): string
    {
        $json = json_encode($data, JSON_THROW_ON_ERROR);

        return self::encrypt($json, $key);
    }

    /**
     * Decrypt a JSON-encoded array from AES-256-GCM ciphertext.
     *
     * @param  string  $encrypted  Base64-encoded ciphertext
     * @param  string  $key  Base64-encoded 32-byte key
     * @return array<mixed> Decrypted array
     *
     * @throws InvalidKeyException If the key is invalid
     * @throws DecryptionException If decryption fails
     */
    public static function decryptArray(string $encrypted, string $key): array
    {
        $json = self::decrypt($encrypted, $key);

        /** @var array<mixed> $data */
        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        return $data;
    }

    /**
     * Validate and decode a base64-encoded encryption key.
     *
     * @throws InvalidKeyException If the key is not a valid 32-byte base64 string
     */
    private static function validateKey(string $key): string
    {
        $decoded = base64_decode($key, true);

        if ($decoded === false || strlen($decoded) !== self::KEY_LENGTH) {
            throw new InvalidKeyException(
                sprintf('Key must be a base64-encoded %d-byte string (got %d bytes).', self::KEY_LENGTH, $decoded === false ? 0 : strlen($decoded))
            );
        }

        return $decoded;
    }
}
