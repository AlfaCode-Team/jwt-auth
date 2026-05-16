<?php

declare(strict_types=1);

namespace AlfaCode\PhpJWT\Storage;

interface TokenStorageInterface
{
    // ── Blacklist (for access + old refresh tokens) ───────────────────────────
    public function blacklist(string $jti, int $ttlSeconds): void;
    public function isBlacklisted(string $jti): bool;

    // ── Refresh token store ───────────────────────────────────────────────────
    public function storeRefreshToken(string $jti, array $data): void;
    public function refreshTokenExists(string $jti): bool;
    public function revokeRefreshToken(string $jti): void;
    public function revokeAllForSubject(string $subject): void;
}
