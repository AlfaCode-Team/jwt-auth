<?php declare(strict_types=1);
namespace AlfaCode\PhpJWT\Exceptions;

class TokenExpiredException extends JWTException
{
    private array $payload;

    public function __construct(string $message, array $payload = [], int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->payload = $payload;
    }

    /** Get the (expired) token payload so callers can read sub, jti, etc. */
    public function getPayload(): array { return $this->payload; }
}
