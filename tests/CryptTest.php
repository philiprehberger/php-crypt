<?php

declare(strict_types=1);

namespace PhilipRehberger\Crypt\Tests;

use PhilipRehberger\Crypt\Crypt;
use PhilipRehberger\Crypt\Exceptions\DecryptionException;
use PhilipRehberger\Crypt\Exceptions\InvalidKeyException;
use PhilipRehberger\Crypt\KeyChain;
use PHPUnit\Framework\TestCase;

class CryptTest extends TestCase
{
    public function test_generate_key_returns_valid_base64(): void
    {
        $key = Crypt::generateKey();

        $this->assertSame(44, strlen($key));
        $decoded = base64_decode($key, true);
        $this->assertNotFalse($decoded);
        $this->assertSame(32, strlen($decoded));
    }

    public function test_encrypt_and_decrypt_roundtrip(): void
    {
        $key = Crypt::generateKey();
        $plaintext = 'Hello, World!';

        $encrypted = Crypt::encrypt($plaintext, $key);
        $decrypted = Crypt::decrypt($encrypted, $key);

        $this->assertSame($plaintext, $decrypted);
        $this->assertNotSame($plaintext, $encrypted);
    }

    public function test_encrypt_produces_unique_ciphertext(): void
    {
        $key = Crypt::generateKey();
        $plaintext = 'same data';

        $encrypted1 = Crypt::encrypt($plaintext, $key);
        $encrypted2 = Crypt::encrypt($plaintext, $key);

        $this->assertNotSame($encrypted1, $encrypted2);
    }

    public function test_decrypt_with_wrong_key_throws(): void
    {
        $key1 = Crypt::generateKey();
        $key2 = Crypt::generateKey();

        $encrypted = Crypt::encrypt('secret', $key1);

        $this->expectException(DecryptionException::class);
        Crypt::decrypt($encrypted, $key2);
    }

    public function test_decrypt_with_tampered_data_throws(): void
    {
        $key = Crypt::generateKey();
        $encrypted = Crypt::encrypt('secret', $key);

        $this->expectException(DecryptionException::class);
        Crypt::decrypt($encrypted.'tampered', $key);
    }

    public function test_invalid_key_throws(): void
    {
        $this->expectException(InvalidKeyException::class);
        Crypt::encrypt('data', 'not-a-valid-key');
    }

    public function test_encrypt_and_decrypt_with_aad(): void
    {
        $key = Crypt::generateKey();
        $plaintext = 'authenticated data';
        $aad = 'context-info';

        $encrypted = Crypt::encrypt($plaintext, $key, $aad);

        $this->assertSame($plaintext, Crypt::decrypt($encrypted, $key, $aad));

        $this->expectException(DecryptionException::class);
        Crypt::decrypt($encrypted, $key, 'wrong-aad');
    }

    public function test_rotate_re_encrypts_with_new_key(): void
    {
        $oldKey = Crypt::generateKey();
        $newKey = Crypt::generateKey();
        $plaintext = 'rotate me';

        $encrypted = Crypt::encrypt($plaintext, $oldKey);
        $rotated = Crypt::rotate($encrypted, $oldKey, $newKey);

        $this->assertSame($plaintext, Crypt::decrypt($rotated, $newKey));
        $this->assertNotSame($encrypted, $rotated);
    }

    public function test_encrypt_array_and_decrypt_array(): void
    {
        $key = Crypt::generateKey();
        $data = ['name' => 'Alice', 'age' => 30, 'active' => true];

        $encrypted = Crypt::encryptArray($data, $key);
        $decrypted = Crypt::decryptArray($encrypted, $key);

        $this->assertSame($data, $decrypted);
    }

    public function test_keychain_encrypt_and_decrypt(): void
    {
        $key = Crypt::generateKey();
        $chain = new KeyChain($key);

        $encrypted = $chain->encrypt('keychain test');
        $this->assertSame('keychain test', $chain->decrypt($encrypted));
    }

    public function test_keychain_decrypts_with_previous_key(): void
    {
        $oldKey = Crypt::generateKey();
        $newKey = Crypt::generateKey();

        $encryptedWithOld = Crypt::encrypt('old secret', $oldKey);

        $chain = new KeyChain($newKey, $oldKey);
        $this->assertSame('old secret', $chain->decrypt($encryptedWithOld));
    }

    public function test_keychain_rotate_all(): void
    {
        $oldKey = Crypt::generateKey();
        $newKey = Crypt::generateKey();

        $ciphertexts = [
            Crypt::encrypt('first', $oldKey),
            Crypt::encrypt('second', $oldKey),
            Crypt::encrypt('third', $oldKey),
        ];

        $chain = new KeyChain($newKey, $oldKey);
        $rotated = $chain->rotateAll($ciphertexts);

        $this->assertCount(3, $rotated);
        $this->assertSame('first', Crypt::decrypt($rotated[0], $newKey));
        $this->assertSame('second', Crypt::decrypt($rotated[1], $newKey));
        $this->assertSame('third', Crypt::decrypt($rotated[2], $newKey));
    }
}
