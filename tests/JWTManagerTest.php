<?php

declare(strict_types=1);

namespace AlfaCode\PhpJWT\Tests;

use AlfaCode\PhpJWT\JWTManager;
use AlfaCode\PhpJWT\Token\JWT;
use AlfaCode\PhpJWT\Token\TokenBuilder;
use AlfaCode\PhpJWT\KeyGenerator;
use AlfaCode\PhpJWT\Storage\FileTokenStorage;
use AlfaCode\PhpJWT\Exceptions\TokenExpiredException;
use AlfaCode\PhpJWT\Exceptions\TokenInvalidException;
use AlfaCode\PhpJWT\Exceptions\TokenBlacklistedException;
use PHPUnit\Framework\TestCase;

class JWTManagerTest extends TestCase
{
    private const SECRET = 'a-very-long-and-secure-secret-key-12345678';
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/jwt_tests_' . uniqid();
    }

    private function manager(?array $config = null, bool $withStorage = false): JWTManager
    {
        $storage = $withStorage ? new FileTokenStorage($this->tmpDir) : null;
        return new JWTManager(array_merge([
            'algorithm'  => 'HS256',
            'secret'     => self::SECRET,
            'access_ttl' => 900,
            'refresh_ttl'=> 3600,
        ], $config ?? []), $storage);
    }

    // ── Basic encoding / decoding ─────────────────────────────────────────────

    public function testEncodeDecodeRoundtrip(): void
    {
        $jwt     = new JWT('HS256');
        $payload = ['sub' => '1', 'foo' => 'bar'];
        $token   = $jwt->encode($payload, self::SECRET);
        $decoded = $jwt->decode($token, self::SECRET);

        $this->assertSame('1', $decoded['sub']);
        $this->assertSame('bar', $decoded['foo']);
    }

    public function testInvalidSignatureThrows(): void
    {
        $jwt   = new JWT('HS256');
        $token = $jwt->encode(['sub' => '1'], self::SECRET);

        $this->expectException(TokenInvalidException::class);
        $jwt->decode($token, 'wrong-secret-key-that-is-long-enough!!');
    }

    public function testExpiredTokenThrows(): void
    {
        $jwt = new JWT('HS256');
        $token = $jwt->encode(['sub' => '1', 'exp' => time() - 10], self::SECRET);

        $this->expectException(TokenExpiredException::class);
        $jwt->decode($token, self::SECRET);
    }

    // ── JWTManager ────────────────────────────────────────────────────────────

    public function testIssueTokensReturnsBothTokens(): void
    {
        $m      = $this->manager();
        $tokens = $m->issueTokens(42);

        $this->assertArrayHasKey('access_token', $tokens);
        $this->assertArrayHasKey('refresh_token', $tokens);
        $this->assertSame('Bearer', $tokens['token_type']);
    }

    public function testValidateAccessTokenReturnsPayload(): void
    {
        $m       = $this->manager();
        $tokens  = $m->issueTokens(42, ['role' => 'admin']);
        $payload = $m->validateAccessToken($tokens['access_token']);

        $this->assertSame('42', $payload['sub']);
        $this->assertSame('admin', $payload['role']);
        $this->assertSame('access', $payload['type']);
    }

    public function testUsingRefreshTokenAsAccessThrows(): void
    {
        $m      = $this->manager();
        $tokens = $m->issueTokens(1);

        $this->expectException(TokenInvalidException::class);
        $m->validateAccessToken($tokens['refresh_token']);
    }

    public function testRefreshIssuesNewAccessToken(): void
    {
        $m      = $this->manager(withStorage: true);
        $tokens = $m->issueTokens(5);

        $new = $m->refresh($tokens['refresh_token']);

        $this->assertNotEmpty($new['access_token']);
        $this->assertNotSame($tokens['access_token'], $new['access_token']);
    }

    public function testRevokedAccessTokenThrows(): void
    {
        $m      = $this->manager(withStorage: true);
        $tokens = $m->issueTokens(3);

        $m->revokeAccessToken($tokens['access_token']);

        $this->expectException(TokenBlacklistedException::class);
        $m->validateAccessToken($tokens['access_token']);
    }

    public function testIsValidReturnsFalseForBadToken(): void
    {
        $m = $this->manager();
        $this->assertFalse($m->isValid('not.a.token'));
    }

    public function testPeekReturnsPayloadWithoutVerification(): void
    {
        $m       = $this->manager();
        $tokens  = $m->issueTokens(7);
        $peeked  = $m->peek($tokens['access_token']);

        $this->assertSame('7', $peeked['sub']);
    }

    // ── TokenBuilder ──────────────────────────────────────────────────────────

    public function testTokenBuilderFluency(): void
    {
        $jwt   = new JWT('HS256');
        $token = (new TokenBuilder())
            ->relatedTo(99)
            ->issuedBy('test')
            ->permittedFor('audience')
            ->expiresAfter(3600)
            ->withClaim('custom', 'value')
            ->build($jwt, self::SECRET);

        $payload = $jwt->decode($token, self::SECRET);
        $this->assertSame('99', $payload['sub']);
        $this->assertSame('value', $payload['custom']);
    }

    // ── RSA tokens ────────────────────────────────────────────────────────────

    public function testRsaSignAndVerify(): void
    {
        $keys = KeyGenerator::generateRsaKeyPair(2048);
        $m    = new JWTManager([
            'algorithm'   => 'RS256',
            'private_key' => $keys['private'],
            'public_key'  => $keys['public'],
            'access_ttl'  => 900,
        ]);

        $tokens  = $m->issueTokens(10);
        $payload = $m->validateAccessToken($tokens['access_token']);
        $this->assertSame('10', $payload['sub']);
    }

    // ── KeyGenerator ─────────────────────────────────────────────────────────

    public function testHmacSecretIsLongEnough(): void
    {
        $secret = KeyGenerator::generateHmacSecret(64);
        $this->assertSame(128, strlen($secret)); // hex-encoded
    }

    public function testJwksHasRequiredFields(): void
    {
        $keys = KeyGenerator::generateRsaKeyPair(2048);
        $jwks = KeyGenerator::publicKeyToJwks($keys['public']);
        $key  = $jwks['keys'][0];

        $this->assertSame('RSA', $key['kty']);
        $this->assertArrayHasKey('n', $key);
        $this->assertArrayHasKey('e', $key);
    }

    protected function tearDown(): void
    {
        // Clean up temp storage
        if (is_dir($this->tmpDir)) {
            array_map('unlink', glob("{$this->tmpDir}/*") ?: []);
            @rmdir($this->tmpDir);
        }
    }
}
