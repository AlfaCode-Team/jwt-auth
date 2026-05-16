<?php

declare(strict_types=1);

namespace AlfaCode\PhpJWT\Token;

use AlfaCode\PhpJWT\Exceptions\JWTException;
use AlfaCode\PhpJWT\Exceptions\TokenExpiredException;
use AlfaCode\PhpJWT\Exceptions\TokenInvalidException;

/**
 * Core JWT implementation.
 * Supports HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512.
 */
class JWT
{
    private const ALGORITHMS = [
        'HS256' => ['family' => 'hmac', 'algo' => 'sha256'],
        'HS384' => ['family' => 'hmac', 'algo' => 'sha384'],
        'HS512' => ['family' => 'hmac', 'algo' => 'sha512'],
        'RS256' => ['family' => 'rsa',  'algo' => OPENSSL_ALGO_SHA256],
        'RS384' => ['family' => 'rsa',  'algo' => OPENSSL_ALGO_SHA384],
        'RS512' => ['family' => 'rsa',  'algo' => OPENSSL_ALGO_SHA512],
        'ES256' => ['family' => 'ec',   'algo' => OPENSSL_ALGO_SHA256],
        'ES384' => ['family' => 'ec',   'algo' => OPENSSL_ALGO_SHA384],
        'ES512' => ['family' => 'ec',   'algo' => OPENSSL_ALGO_SHA512],
    ];

    private string $algorithm;
    private int $leeway; // seconds of clock skew tolerance

    public function __construct(string $algorithm = 'HS256', int $leeway = 0)
    {
        if (!isset(self::ALGORITHMS[$algorithm])) {
            throw new JWTException("Unsupported algorithm: {$algorithm}");
        }
        $this->algorithm = $algorithm;
        $this->leeway    = $leeway;
    }

    /**
     * Encode a payload into a signed JWT string.
     */
    public function encode(array $payload, string $key): string
    {
        $header = $this->base64UrlEncode(json_encode([
            'typ' => 'JWT',
            'alg' => $this->algorithm,
        ]));

        $body = $this->base64UrlEncode(json_encode($payload));
        $signingInput = "{$header}.{$body}";
        $signature    = $this->sign($signingInput, $key);

        return "{$signingInput}.{$this->base64UrlEncode($signature)}";
    }

    /**
     * Decode and validate a JWT string, returning the payload.
     */
    public function decode(string $token, string $key): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new TokenInvalidException('JWT must have exactly 3 segments.');
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $header = json_decode($this->base64UrlDecode($headerB64), true);
        if (!$header || !isset($header['alg'])) {
            throw new TokenInvalidException('Invalid JWT header.');
        }

        if ($header['alg'] !== $this->algorithm) {
            throw new TokenInvalidException(
                "Algorithm mismatch: expected {$this->algorithm}, got {$header['alg']}."
            );
        }

        $payload = json_decode($this->base64UrlDecode($payloadB64), true);
        if (!is_array($payload)) {
            throw new TokenInvalidException('Invalid JWT payload.');
        }

        $signature    = $this->base64UrlDecode($signatureB64);
        $signingInput = "{$headerB64}.{$payloadB64}";

        if (!$this->verify($signingInput, $signature, $key)) {
            throw new TokenInvalidException('JWT signature verification failed.');
        }

        $now = time();

        // Check expiry
        if (isset($payload['exp']) && ($payload['exp'] + $this->leeway) < $now) {
            throw new TokenExpiredException('JWT has expired.', $payload);
        }

        // Check not-before
        if (isset($payload['nbf']) && ($payload['nbf'] - $this->leeway) > $now) {
            throw new TokenInvalidException('JWT is not yet valid (nbf).');
        }

        // Check issued-at sanity
        if (isset($payload['iat']) && ($payload['iat'] - $this->leeway) > $now) {
            throw new TokenInvalidException('JWT issued-at is in the future (iat).');
        }

        return $payload;
    }

    // ──────────────────────────────────────────────
    // Signing & verification
    // ──────────────────────────────────────────────

    private function sign(string $data, string $key): string
    {
        $meta = self::ALGORITHMS[$this->algorithm];

        return match ($meta['family']) {
            'hmac' => hash_hmac($meta['algo'], $data, $key, true),
            'rsa'  => $this->signRsa($data, $key, $meta['algo']),
            'ec'   => $this->signEc($data, $key, $meta['algo']),
            default => throw new JWTException("Unknown algorithm family: {$meta['family']}"),
        };
    }

    private function verify(string $data, string $signature, string $key): bool
    {
        $meta = self::ALGORITHMS[$this->algorithm];

        return match ($meta['family']) {
            'hmac' => hash_equals(hash_hmac($meta['algo'], $data, $key, true), $signature),
            'rsa'  => $this->verifyRsa($data, $signature, $key, $meta['algo']),
            'ec'   => $this->verifyEc($data, $signature, $key, $meta['algo']),
            default => throw new JWTException("Unknown algorithm family: {$meta['family']}"),
        };
    }

    private function signRsa(string $data, string $privateKey, int $algo): string
    {
        $key = openssl_pkey_get_private($privateKey);
        if (!$key) {
            throw new JWTException('Invalid RSA private key.');
        }
        $success = openssl_sign($data, $signature, $key, $algo);
        if (!$success) {
            throw new JWTException('RSA signing failed.');
        }
        return $signature;
    }

    private function verifyRsa(string $data, string $signature, string $publicKey, int $algo): bool
    {
        $key = openssl_pkey_get_public($publicKey);
        if (!$key) {
            throw new JWTException('Invalid RSA public key.');
        }
        return openssl_verify($data, $signature, $key, $algo) === 1;
    }

    private function signEc(string $data, string $privateKey, int $algo): string
    {
        return $this->signRsa($data, $privateKey, $algo); // OpenSSL handles EC the same way
    }

    private function verifyEc(string $data, string $signature, string $publicKey, int $algo): bool
    {
        return $this->verifyRsa($data, $signature, $publicKey, $algo);
    }

    // ──────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────

    public function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new TokenInvalidException('Base64 decoding failed.');
        }
        return $decoded;
    }
}
