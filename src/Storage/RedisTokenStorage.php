<?php

declare(strict_types=1);

namespace AlfaCode\PhpJWT\Storage;

use Redis;

/**
 * Redis-backed token storage.
 *
 * Requires the phpredis extension (pecl install redis) or Predis.
 * This implementation uses the native phpredis client.
 *
 * Key layout:
 *   jwt:bl:{jti}       – blacklisted JTI  (value: "1", TTL matches token)
 *   jwt:rt:{jti}       – refresh token data (JSON)
 *   jwt:sub:{subject}  – SET of active refresh JTIs for that subject
 */
class RedisTokenStorage implements TokenStorageInterface
{
    private Redis $redis;
    private string $prefix;

    public function __construct(Redis $redis, string $prefix = 'jwt')
    {
        $this->redis  = $redis;
        $this->prefix = $prefix;
    }

    // ── Blacklist ─────────────────────────────────────────────────────────────

    public function blacklist(string $jti, int $ttlSeconds): void
    {
        $this->redis->setex($this->key('bl', $jti), max(1, $ttlSeconds), '1');
    }

    public function isBlacklisted(string $jti): bool
    {
        return (bool) $this->redis->exists($this->key('bl', $jti));
    }

    // ── Refresh tokens ────────────────────────────────────────────────────────

    public function storeRefreshToken(string $jti, array $data): void
    {
        $ttl     = max(1, ($data['expires_at'] ?? time() + 604800) - time());
        $subject = $data['sub'] ?? 'unknown';

        // Store the token data
        $this->redis->setex($this->key('rt', $jti), $ttl, json_encode($data));

        // Track it under the subject set
        $this->redis->sAdd($this->key('sub', $subject), $jti);
        $this->redis->expire($this->key('sub', $subject), $ttl + 86400); // extra buffer
    }

    public function refreshTokenExists(string $jti): bool
    {
        return (bool) $this->redis->exists($this->key('rt', $jti));
    }

    public function revokeRefreshToken(string $jti): void
    {
        $raw = $this->redis->get($this->key('rt', $jti));
        if ($raw) {
            $data    = json_decode($raw, true);
            $subject = $data['sub'] ?? null;
            if ($subject) {
                $this->redis->sRem($this->key('sub', $subject), $jti);
            }
        }
        $this->redis->del($this->key('rt', $jti));
    }

    public function revokeAllForSubject(string $subject): void
    {
        $jtis = $this->redis->sMembers($this->key('sub', $subject));
        foreach ($jtis as $jti) {
            $this->redis->del($this->key('rt', $jti));
            // Blacklist immediately (short TTL; they'd expire anyway)
            $this->redis->setex($this->key('bl', $jti), 3600, '1');
        }
        $this->redis->del($this->key('sub', $subject));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function key(string $type, string $id): string
    {
        return "{$this->prefix}:{$type}:{$id}";
    }
}
