<?php

declare(strict_types=1);

namespace PhilipRehberger\Crypt\Exceptions;

use InvalidArgumentException;

/**
 * Thrown when an encryption key is invalid or malformed.
 */
class InvalidKeyException extends InvalidArgumentException {}
