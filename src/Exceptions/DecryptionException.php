<?php

declare(strict_types=1);

namespace PhilipRehberger\Crypt\Exceptions;

use RuntimeException;

/**
 * Thrown when decryption fails due to invalid ciphertext, wrong key, or tampered data.
 */
class DecryptionException extends RuntimeException {}
