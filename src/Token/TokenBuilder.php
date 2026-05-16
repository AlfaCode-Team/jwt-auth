<?php

declare(strict_types=1);

namespace AlfaCode\PhpJWT\Token;

use DateTimeImmutable;
use DateInterval;

/**
 * Fluent builder for constructing JWT payloads before encoding.
 *
 * Example:
 *   $token = (new TokenBuilder())
 *       ->issuedBy('https://api.example.com')
 *       ->permittedFor('https://app.example.com')
 *       ->identifiedBy(bin2hex(random_bytes(16)))
 *       ->expiresAfter(3600)
 *       ->withClaim('uid', 42)
 *       ->withClaim('roles', ['admin'])
 *       ->build($jwtInstance, $secretKey);
 */
class TokenBuilder
{
    private array $claims = [];

    public function __construct()
    {
        $this->claims['iat'] = time();
    }

    // ──────────────────────────────────────────────
    // Standard claims (RFC 7519)
    // ──────────────────────────────────────────────

    /** iss – the issuer (who created the token) */
    public function issuedBy(string $issuer): static
    {
        $this->claims['iss'] = $issuer;
        return $this;
    }

    /** aud – the audience (who the token is intended for) */
    public function permittedFor(string|array $audience): static
    {
        $this->claims['aud'] = is_array($audience) ? $audience : [$audience];
        return $this;
    }

    /** sub – the subject (whom the token refers to, e.g. user ID) */
    public function relatedTo(string|int $subject): static
    {
        $this->claims['sub'] = (string) $subject;
        return $this;
    }

    /** jti – unique token identifier */
    public function identifiedBy(string $id): static
    {
        $this->claims['jti'] = $id;
        return $this;
    }

    /** exp – expires at a specific Unix timestamp */
    public function expiresAt(int|DateTimeImmutable $time): static
    {
        $this->claims['exp'] = $time instanceof DateTimeImmutable ? $time->getTimestamp() : $time;
        return $this;
    }

    /** exp – expires N seconds from now */
    public function expiresAfter(int $seconds): static
    {
        $this->claims['exp'] = time() + $seconds;
        return $this;
    }

    /** nbf – not valid before this timestamp */
    public function canOnlyBeUsedAfter(int|DateTimeImmutable $time): static
    {
        $this->claims['nbf'] = $time instanceof DateTimeImmutable ? $time->getTimestamp() : $time;
        return $this;
    }

    /** iat – override the issued-at timestamp */
    public function issuedAt(int $time): static
    {
        $this->claims['iat'] = $time;
        return $this;
    }

    // ──────────────────────────────────────────────
    // Custom claims
    // ──────────────────────────────────────────────

    /** Add any custom claim (private or public) */
    public function withClaim(string $name, mixed $value): static
    {
        $this->claims[$name] = $value;
        return $this;
    }

    /** Bulk-add custom claims */
    public function withClaims(array $claims): static
    {
        foreach ($claims as $k => $v) {
            $this->withClaim($k, $v);
        }
        return $this;
    }

    // ──────────────────────────────────────────────
    // Build
    // ──────────────────────────────────────────────

    /**
     * Encode and sign the token, returning the compact JWT string.
     */
    public function build(JWT $jwt, string $key): string
    {
        return $jwt->encode($this->claims, $key);
    }

    /**
     * Return the raw claims array (for inspection before signing).
     */
    public function getClaims(): array
    {
        return $this->claims;
    }
}
