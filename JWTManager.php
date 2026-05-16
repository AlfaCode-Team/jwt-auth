<?php

declare(strict_types=1);

namespace PhpJWT;

use PhpJWT\Token\JWT;
use PhpJWT\Token\TokenBuilder;
use PhpJWT\Storage\TokenStorageInterface;
use PhpJWT\Exceptions\JWTException;
use PhpJWT\Exceptions\TokenExpiredException;
use PhpJWT\Exceptions\TokenInvalidException;
use PhpJWT\Exceptions\TokenBlacklistedException;

/**
 * High-level manager orchestrating access tokens, refresh tokens,
 * rotation, revocation, and optional per-user key support.
 */
class JWTManager
{
    private JWT $jwt;
    private array $config;
    private ?TokenStorageInterface $storage;

    public function __construct(array $config = [], ?TokenStorageInterface $storage = null)
    {
        $defaults = [
            'algorithm'            => 'HS256',
            'secret'               => '',
            'private_key'          => null,   // For RS*/ES* algorithms
            'public_key'           => null,
            'access_ttl'           => 900,    // 15 minutes
            'refresh_ttl'          => 604800, // 7 days
            'issuer'               => '',
            'audience'             => [],
            'leeway'               => 0,
            'blacklist_enabled'    => true,
            'refresh_rotation'     => true,   // Rotate refresh token on each use
            'single_use_refresh'   => true,   // Old refresh token is revoked on rotation
        ];

        $this->config  = array_merge($defaults, $config);
        $this->storage = $storage;
        $this->jwt     = new JWT($this->config['algorithm'], $this->config['leeway']);
    }

    // ──────────────────────────────────────────────
    // Token creation
    // ──────────────────────────────────────────────

    /**
     * Create an access + refresh token pair for a given subject (e.g. user ID).
     *
     * @param  string|int  $subject     User/entity identifier
     * @param  array       $claims      Extra custom claims for the access token
     * @param  array       $refreshMeta Extra data stored in the refresh token
     * @return array{access_token: string, refresh_token: string, expires_in: int, token_type: string}
     */
    public function issueTokens(string|int $subject, array $claims = [], array $refreshMeta = []): array
    {
        $accessToken  = $this->createAccessToken($subject, $claims);
        $refreshToken = $this->createRefreshToken($subject, $refreshMeta);

        return [
            'token_type'    => 'Bearer',
            'access_token'  => $accessToken,
            'expires_in'    => $this->config['access_ttl'],
            'refresh_token' => $refreshToken,
        ];
    }

    /**
     * Create a stand-alone access token.
     */
    public function createAccessToken(string|int $subject, array $extraClaims = []): string
    {
        $jti = $this->generateJti();

        $builder = (new TokenBuilder())
            ->relatedTo($subject)
            ->identifiedBy($jti)
            ->expiresAfter($this->config['access_ttl'])
            ->withClaim('type', 'access')
            ->withClaims($extraClaims);

        if ($this->config['issuer']) {
            $builder->issuedBy($this->config['issuer']);
        }
        if (!empty($this->config['audience'])) {
            $builder->permittedFor($this->config['audience']);
        }

        return $builder->build($this->jwt, $this->getSigningKey());
    }

    /**
     * Create a refresh token.
     */
    public function createRefreshToken(string|int $subject, array $meta = []): string
    {
        $jti = $this->generateJti();

        $builder = (new TokenBuilder())
            ->relatedTo($subject)
            ->identifiedBy($jti)
            ->expiresAfter($this->config['refresh_ttl'])
            ->withClaim('type', 'refresh')
            ->withClaims($meta);

        if ($this->config['issuer']) {
            $builder->issuedBy($this->config['issuer']);
        }

        $token = $builder->build($this->jwt, $this->getSigningKey());

        // Persist refresh token metadata
        if ($this->storage) {
            $this->storage->storeRefreshToken($jti, [
                'sub'        => (string) $subject,
                'expires_at' => time() + $this->config['refresh_ttl'],
                'meta'       => $meta,
            ]);
        }

        return $token;
    }

    // ──────────────────────────────────────────────
    // Token validation
    // ──────────────────────────────────────────────

    /**
     * Validate an access token and return its payload.
     *
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     * @throws TokenBlacklistedException
     */
    public function validateAccessToken(string $token): array
    {
        $payload = $this->jwt->decode($token, $this->getVerificationKey());

        if (($payload['type'] ?? null) !== 'access') {
            throw new TokenInvalidException('Token is not an access token.');
        }

        $this->checkBlacklist($payload['jti'] ?? '');

        return $payload;
    }

    /**
     * Validate a refresh token and return its payload.
     *
     * @throws TokenInvalidException
     * @throws TokenExpiredException
     * @throws TokenBlacklistedException
     */
    public function validateRefreshToken(string $token): array
    {
        $payload = $this->jwt->decode($token, $this->getVerificationKey());

        if (($payload['type'] ?? null) !== 'refresh') {
            throw new TokenInvalidException('Token is not a refresh token.');
        }

        $jti = $payload['jti'] ?? '';
        $this->checkBlacklist($jti);

        // Verify against persistent storage if available
        if ($this->storage && !$this->storage->refreshTokenExists($jti)) {
            throw new TokenInvalidException('Refresh token not found in storage (likely revoked).');
        }

        return $payload;
    }

    // ──────────────────────────────────────────────
    // Refresh flow
    // ──────────────────────────────────────────────

    /**
     * Consume a refresh token and issue a new access token.
     * If rotation is enabled, also issues a new refresh token.
     *
     * @return array{access_token: string, refresh_token: string|null, expires_in: int, token_type: string}
     */
    public function refresh(string $refreshToken, array $newAccessClaims = []): array
    {
        $payload  = $this->validateRefreshToken($refreshToken);
        $subject  = $payload['sub'];
        $oldJti   = $payload['jti'] ?? '';

        $newAccessToken  = $this->createAccessToken($subject, $newAccessClaims);
        $newRefreshToken = null;

        if ($this->config['refresh_rotation']) {
            // Revoke the old refresh token
            if ($this->config['single_use_refresh']) {
                $this->revokeRefreshToken($oldJti);
            }
            $newRefreshToken = $this->createRefreshToken($subject);
        }

        return [
            'token_type'    => 'Bearer',
            'access_token'  => $newAccessToken,
            'expires_in'    => $this->config['access_ttl'],
            'refresh_token' => $newRefreshToken ?? $refreshToken,
        ];
    }

    // ──────────────────────────────────────────────
    // Revocation
    // ──────────────────────────────────────────────

    /**
     * Blacklist an access token by its JTI (e.g. on logout).
     */
    public function revokeAccessToken(string $token): void
    {
        try {
            $payload = $this->jwt->decode($token, $this->getVerificationKey());
            $jti     = $payload['jti'] ?? null;
            $ttl     = ($payload['exp'] ?? time()) - time();

            if ($jti && $this->storage && $ttl > 0) {
                $this->storage->blacklist($jti, $ttl);
            }
        } catch (\Throwable) {
            // Silently ignore invalid tokens; revocation of an invalid token is a no-op
        }
    }

    /**
     * Revoke a specific refresh token by its JTI.
     */
    public function revokeRefreshToken(string $jti): void
    {
        if ($this->storage) {
            $this->storage->revokeRefreshToken($jti);
            $this->storage->blacklist($jti, $this->config['refresh_ttl']);
        }
    }

    /**
     * Revoke ALL refresh tokens for a given subject (logout from all devices).
     */
    public function revokeAllForSubject(string|int $subject): void
    {
        if ($this->storage) {
            $this->storage->revokeAllForSubject((string) $subject);
        }
    }

    // ──────────────────────────────────────────────
    // Introspection
    // ──────────────────────────────────────────────

    /**
     * Decode a token WITHOUT validating the signature (for inspection only).
     */
    public function peek(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new TokenInvalidException('Token does not have 3 segments.');
        }
        $payload = json_decode(
            (new JWT())->base64UrlDecode($parts[1]),
            true
        );
        if (!is_array($payload)) {
            throw new TokenInvalidException('Cannot decode token payload.');
        }
        return $payload;
    }

    /**
     * Returns whether an access token is currently valid (no exception).
     */
    public function isValid(string $token): bool
    {
        try {
            $this->validateAccessToken($token);
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Returns seconds until a token expires (negative if already expired).
     */
    public function expiresIn(string $token): int
    {
        $payload = $this->peek($token);
        return ($payload['exp'] ?? 0) - time();
    }

    // ──────────────────────────────────────────────
    // Key management helpers
    // ──────────────────────────────────────────────

    private function getSigningKey(): string
    {
        $family = $this->getAlgorithmFamily();
        if ($family !== 'hmac') {
            $key = $this->config['private_key'] ?? null;
            if (!$key) {
                throw new JWTException("private_key must be set for {$this->config['algorithm']}.");
            }
            return $key;
        }
        $key = $this->config['secret'] ?? '';
        if (strlen($key) < 32) {
            throw new JWTException('HMAC secret must be at least 32 characters.');
        }
        return $key;
    }

    private function getVerificationKey(): string
    {
        $family = $this->getAlgorithmFamily();
        if ($family !== 'hmac') {
            return $this->config['public_key'] ?? $this->config['private_key'] ?? '';
        }
        return $this->config['secret'];
    }

    private function getAlgorithmFamily(): string
    {
        return match (true) {
            str_starts_with($this->config['algorithm'], 'HS') => 'hmac',
            str_starts_with($this->config['algorithm'], 'RS') => 'rsa',
            str_starts_with($this->config['algorithm'], 'ES') => 'ec',
            default => 'unknown',
        };
    }

    // ──────────────────────────────────────────────
    // Internal utilities
    // ──────────────────────────────────────────────

    private function generateJti(): string
    {
        return bin2hex(random_bytes(16));
    }

    private function checkBlacklist(string $jti): void
    {
        if (!$this->config['blacklist_enabled'] || !$this->storage || !$jti) {
            return;
        }
        if ($this->storage->isBlacklisted($jti)) {
            throw new TokenBlacklistedException("Token (jti: {$jti}) has been revoked.");
        }
    }

    public function getConfig(): array
    {
        return $this->config;
    }
}
