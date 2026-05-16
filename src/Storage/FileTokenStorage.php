<?php

declare(strict_types=1);

namespace AlfaCode\PhpJWT\Storage;

/**
 * File-system token storage — no external dependencies required.
 * Suitable for development and low-traffic applications.
 *
 * Data is stored in a JSON file; protected by an exclusive lock on writes.
 */
class FileTokenStorage implements TokenStorageInterface
{
    private string $path;

    public function __construct(string $storagePath)
    {
        $this->path = rtrim($storagePath, '/');
        if (!is_dir($this->path) && !mkdir($this->path, 0700, true)) {
            throw new \RuntimeException("Cannot create storage directory: {$this->path}");
        }
    }

    // ── Blacklist ─────────────────────────────────────────────────────────────

    public function blacklist(string $jti, int $ttlSeconds): void
    {
        $store          = $this->read('blacklist');
        $store[$jti]    = time() + $ttlSeconds;
        $this->write('blacklist', $store);
    }

    public function isBlacklisted(string $jti): bool
    {
        $store = $this->read('blacklist');
        return isset($store[$jti]) && $store[$jti] > time();
    }

    // ── Refresh tokens ────────────────────────────────────────────────────────

    public function storeRefreshToken(string $jti, array $data): void
    {
        $store        = $this->read('refresh_tokens');
        $store[$jti]  = array_merge($data, ['revoked' => false]);
        $this->write('refresh_tokens', $store);
    }

    public function refreshTokenExists(string $jti): bool
    {
        $store = $this->read('refresh_tokens');
        if (!isset($store[$jti])) {
            return false;
        }
        $entry = $store[$jti];
        return !$entry['revoked'] && ($entry['expires_at'] ?? 0) > time();
    }

    public function revokeRefreshToken(string $jti): void
    {
        $store = $this->read('refresh_tokens');
        if (isset($store[$jti])) {
            $store[$jti]['revoked'] = true;
            $this->write('refresh_tokens', $store);
        }
    }

    public function revokeAllForSubject(string $subject): void
    {
        $store   = $this->read('refresh_tokens');
        $changed = false;
        foreach ($store as $jti => $entry) {
            if (($entry['sub'] ?? '') === $subject && !$entry['revoked']) {
                $store[$jti]['revoked'] = true;
                $changed = true;
            }
        }
        if ($changed) {
            $this->write('refresh_tokens', $store);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private function read(string $bucket): array
    {
        $file = "{$this->path}/{$bucket}.json";
        if (!file_exists($file)) {
            return [];
        }
        $content = file_get_contents($file);
        return $content ? (json_decode($content, true) ?? []) : [];
    }

    private function write(string $bucket, array $data): void
    {
        $file = "{$this->path}/{$bucket}.json";
        $fp   = fopen($file, 'c');
        if (!$fp) {
            throw new \RuntimeException("Cannot open storage file: {$file}");
        }
        flock($fp, LOCK_EX);
        ftruncate($fp, 0);
        fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
        flock($fp, LOCK_UN);
        fclose($fp);
    }

    /**
     * Clean up expired entries (call from cron or maintenance script).
     */
    public function purgeExpired(): void
    {
        $bl  = $this->read('blacklist');
        $now = time();
        $this->write('blacklist', array_filter($bl, fn($exp) => $exp > $now));

        $rt = $this->read('refresh_tokens');
        $this->write('refresh_tokens', array_filter(
            $rt,
            fn($e) => ($e['expires_at'] ?? 0) > $now
        ));
    }
}
