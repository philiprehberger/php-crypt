<?php

declare(strict_types=1);

namespace PhilipRehberger\Crypt;

use PhilipRehberger\Crypt\Exceptions\DecryptionException;

/**
 * Multi-key encryption manager with automatic key rotation support.
 *
 * Encrypts using the current key and attempts decryption with all known keys,
 * enabling seamless key rotation without downtime.
 */
class KeyChain
{
    /**
     * @var list<string> All keys in order: current key first, then previous keys
     */
    private readonly array $keys;

    /**
     * Create a new KeyChain instance.
     *
     * @param  string  $currentKey  The active key used for encryption
     * @param  string  ...$previousKeys  Previous keys used only for decryption
     */
    public function __construct(
        private readonly string $currentKey,
        string ...$previousKeys,
    ) {
        $this->keys = [$this->currentKey, ...$previousKeys];
    }

    /**
     * Encrypt data using the current key.
     *
     * @param  string  $data  Plaintext to encrypt
     * @return string Base64-encoded ciphertext
     */
    public function encrypt(string $data): string
    {
        return Crypt::encrypt($data, $this->currentKey);
    }

    /**
     * Decrypt data by trying all keys in order.
     *
     * Attempts decryption with the current key first, then falls back to
     * previous keys. This allows transparent decryption during key rotation.
     *
     * @param  string  $encrypted  Base64-encoded ciphertext
     * @return string Decrypted plaintext
     *
     * @throws DecryptionException If no key can decrypt the data
     */
    public function decrypt(string $encrypted): string
    {
        foreach ($this->keys as $key) {
            try {
                return Crypt::decrypt($encrypted, $key);
            } catch (DecryptionException) {
                continue;
            }
        }

        throw new DecryptionException('None of the keys in the chain could decrypt the data.');
    }

    /**
     * Re-encrypt all ciphertexts with the current key.
     *
     * Each ciphertext is decrypted with whichever key works, then
     * re-encrypted with the current key.
     *
     * @param  list<string>  $ciphertexts  Array of base64-encoded ciphertexts
     * @return list<string> Array of re-encrypted ciphertexts
     *
     * @throws DecryptionException If any ciphertext cannot be decrypted
     */
    public function rotateAll(array $ciphertexts): array
    {
        return array_map(function (string $encrypted): string {
            $plaintext = $this->decrypt($encrypted);

            return Crypt::encrypt($plaintext, $this->currentKey);
        }, $ciphertexts);
    }
}
