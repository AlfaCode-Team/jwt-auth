<?php

declare(strict_types=1);

namespace AlfaCode\PhpJWT\Storage;

use PDO;

/**
 * PDO-backed token storage (MySQL / PostgreSQL / SQLite).
 *
 * Run the bundled migration before use:
 *   php vendor/bin/jwt-migrate --dsn="mysql:host=localhost;dbname=mydb" --user=root --pass=secret
 *
 * Or execute schema.sql manually.
 */
class PDOTokenStorage implements TokenStorageInterface
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    // ── Schema helper ─────────────────────────────────────────────────────────

    /**
     * Create the required tables (idempotent).
     */
    public function migrate(): void
    {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS jwt_blacklist (
                jti        VARCHAR(64)  NOT NULL PRIMARY KEY,
                expires_at BIGINT       NOT NULL,
                created_at BIGINT       NOT NULL DEFAULT (STRFTIME('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS jwt_refresh_tokens (
                jti        VARCHAR(64)  NOT NULL PRIMARY KEY,
                subject    VARCHAR(255) NOT NULL,
                payload    TEXT         NOT NULL,
                expires_at BIGINT       NOT NULL,
                created_at BIGINT       NOT NULL DEFAULT (STRFTIME('%s','now')),
                revoked_at BIGINT       DEFAULT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_refresh_subject ON jwt_refresh_tokens(subject);
            CREATE INDEX IF NOT EXISTS idx_bl_expires ON jwt_blacklist(expires_at);
        ");
    }

    // ── Blacklist ─────────────────────────────────────────────────────────────

    public function blacklist(string $jti, int $ttlSeconds): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO jwt_blacklist (jti, expires_at)
            VALUES (:jti, :exp)
            ON CONFLICT(jti) DO UPDATE SET expires_at = :exp
        ");
        $stmt->execute([':jti' => $jti, ':exp' => time() + $ttlSeconds]);
    }

    public function isBlacklisted(string $jti): bool
    {
        $stmt = $this->pdo->prepare(
            "SELECT 1 FROM jwt_blacklist WHERE jti = :jti AND expires_at > :now LIMIT 1"
        );
        $stmt->execute([':jti' => $jti, ':now' => time()]);
        return (bool) $stmt->fetchColumn();
    }

    // ── Refresh tokens ────────────────────────────────────────────────────────

    public function storeRefreshToken(string $jti, array $data): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO jwt_refresh_tokens (jti, subject, payload, expires_at)
            VALUES (:jti, :sub, :payload, :exp)
        ");
        $stmt->execute([
            ':jti'     => $jti,
            ':sub'     => $data['sub'] ?? '',
            ':payload' => json_encode($data),
            ':exp'     => $data['expires_at'] ?? time() + 604800,
        ]);
    }

    public function refreshTokenExists(string $jti): bool
    {
        $stmt = $this->pdo->prepare("
            SELECT 1 FROM jwt_refresh_tokens
            WHERE jti = :jti AND revoked_at IS NULL AND expires_at > :now
            LIMIT 1
        ");
        $stmt->execute([':jti' => $jti, ':now' => time()]);
        return (bool) $stmt->fetchColumn();
    }

    public function revokeRefreshToken(string $jti): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE jwt_refresh_tokens SET revoked_at = :now WHERE jti = :jti
        ");
        $stmt->execute([':jti' => $jti, ':now' => time()]);
    }

    public function revokeAllForSubject(string $subject): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE jwt_refresh_tokens
            SET revoked_at = :now
            WHERE subject = :sub AND revoked_at IS NULL
        ");
        $stmt->execute([':sub' => $subject, ':now' => time()]);
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    /**
     * Purge expired blacklist entries and old refresh tokens.
     * Call from a scheduled job / cron.
     */
    public function purgeExpired(): int
    {
        $now = time();
        $a   = $this->pdo->prepare("DELETE FROM jwt_blacklist WHERE expires_at <= :now");
        $a->execute([':now' => $now]);

        $b = $this->pdo->prepare("DELETE FROM jwt_refresh_tokens WHERE expires_at <= :now");
        $b->execute([':now' => $now]);

        return $a->rowCount() + $b->rowCount();
    }
}
