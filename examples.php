<?php

declare(strict_types=1);

/**
 * ============================================================
 *  PHP JWT Auth — Complete Usage Examples
 * ============================================================
 *
 * Run any section independently. Adjust paths as needed.
 */

require __DIR__ . '/vendor/autoload.php';

use AlfaCode\PhpJWT\JWTManager;
use AlfaCode\PhpJWT\KeyGenerator;
use AlfaCode\PhpJWT\Token\JWT;
use AlfaCode\PhpJWT\Token\TokenBuilder;
use AlfaCode\PhpJWT\Storage\FileTokenStorage;
use AlfaCode\PhpJWT\Storage\PDOTokenStorage;
use AlfaCode\PhpJWT\Storage\RedisTokenStorage;
use AlfaCode\PhpJWT\Middleware\JWTMiddleware;
use AlfaCode\PhpJWT\Exceptions\TokenExpiredException;
use AlfaCode\PhpJWT\Exceptions\TokenInvalidException;
use AlfaCode\PhpJWT\Exceptions\TokenBlacklistedException;

// ────────────────────────────────────────────────────────────
//  1. BASIC SETUP — HMAC (HS256, no database required)
// ────────────────────────────────────────────────────────────

$manager = new JWTManager([
    'algorithm'  => 'HS256',
    'secret'     => 'your-super-secret-key-at-least-32-chars!!',
    'access_ttl' => 900,     // 15 minutes
    'refresh_ttl'=> 604800,  // 7 days
    'issuer'     => 'https://api.example.com',
    'audience'   => ['https://app.example.com'],
]);

// Issue an access + refresh token pair for user #42
$tokens = $manager->issueTokens(42, [
    'email' => 'alice@example.com',
    'roles' => ['user', 'editor'],
]);

echo "=== Token Pair ===\n";
echo "Access Token:  " . $tokens['access_token'] . "\n";
echo "Refresh Token: " . $tokens['refresh_token'] . "\n";
echo "Expires In:    " . $tokens['expires_in'] . "s\n\n";

// ────────────────────────────────────────────────────────────
//  2. VALIDATE AN ACCESS TOKEN
// ────────────────────────────────────────────────────────────

try {
    $payload = $manager->validateAccessToken($tokens['access_token']);
    echo "=== Valid Access Token ===\n";
    echo "Subject: " . $payload['sub'] . "\n";
    echo "Email:   " . $payload['email'] . "\n";
    echo "Roles:   " . implode(', ', $payload['roles']) . "\n\n";
} catch (TokenExpiredException $e) {
    echo "Token expired. Payload: " . json_encode($e->getPayload()) . "\n";
} catch (TokenInvalidException $e) {
    echo "Invalid token: " . $e->getMessage() . "\n";
} catch (TokenBlacklistedException $e) {
    echo "Token revoked: " . $e->getMessage() . "\n";
}

// ────────────────────────────────────────────────────────────
//  3. REFRESH TOKENS
// ────────────────────────────────────────────────────────────

// With file storage so refresh tokens are persisted:
$storage = new FileTokenStorage(__DIR__ . '/storage/jwt');

$managerWithStorage = new JWTManager([
    'algorithm'        => 'HS256',
    'secret'           => 'your-super-secret-key-at-least-32-chars!!',
    'access_ttl'       => 900,
    'refresh_ttl'      => 604800,
    'refresh_rotation' => true,   // New refresh token issued on each refresh
    'single_use_refresh'=> true,  // Old refresh token revoked immediately
], $storage);

$tokens2 = $managerWithStorage->issueTokens(42);

// Later, when access token expires, refresh it:
$newTokens = $managerWithStorage->refresh($tokens2['refresh_token']);
echo "=== Refreshed Tokens ===\n";
echo "New Access Token:  " . $newTokens['access_token'] . "\n";
echo "New Refresh Token: " . $newTokens['refresh_token'] . "\n\n";

// ────────────────────────────────────────────────────────────
//  4. LOGOUT (revoke tokens)
// ────────────────────────────────────────────────────────────

// Revoke the current access token (blacklist it)
$managerWithStorage->revokeAccessToken($newTokens['access_token']);

// Revoke ALL sessions for a user (e.g. "logout from all devices")
$managerWithStorage->revokeAllForSubject(42);

echo "Tokens revoked.\n\n";

// ────────────────────────────────────────────────────────────
//  5. FLUENT TOKEN BUILDER (full control)
// ────────────────────────────────────────────────────────────

$jwt = new JWT('HS512');

$customToken = (new TokenBuilder())
    ->issuedBy('https://api.example.com')
    ->permittedFor(['https://app.example.com', 'https://mobile.example.com'])
    ->relatedTo(99)
    ->identifiedBy(bin2hex(random_bytes(16)))
    ->expiresAfter(3600)
    ->canOnlyBeUsedAfter(time() + 60)  // Not valid for the first 60 seconds
    ->withClaim('scope', 'read:posts write:posts')
    ->withClaim('tier', 'premium')
    ->build($jwt, 'your-hs512-secret-at-least-32-chars!!!!');

echo "=== Custom Token ===\n";
echo $customToken . "\n\n";

// ────────────────────────────────────────────────────────────
//  6. RSA / EC ASYMMETRIC KEYS
// ────────────────────────────────────────────────────────────

echo "=== Generating RSA Key Pair ===\n";
$rsaKeys = KeyGenerator::generateRsaKeyPair(2048); // Use 4096 in production
// Save these to files in production:
// file_put_contents('/etc/jwt/private.pem', $rsaKeys['private']);
// file_put_contents('/etc/jwt/public.pem',  $rsaKeys['public']);

$rsaManager = new JWTManager([
    'algorithm'   => 'RS256',
    'private_key' => $rsaKeys['private'],
    'public_key'  => $rsaKeys['public'],
    'access_ttl'  => 900,
]);

$rsaTokens = $rsaManager->issueTokens(7, ['role' => 'admin']);
$rsaPayload = $rsaManager->validateAccessToken($rsaTokens['access_token']);
echo "RSA Token subject: " . $rsaPayload['sub'] . "\n\n";

// Export public key as JWKS (publish at /.well-known/jwks.json)
$jwks = KeyGenerator::publicKeyToJwks($rsaKeys['public'], 'key-2024', 'RS256');
echo "=== JWKS ===\n";
echo json_encode($jwks, JSON_PRETTY_PRINT) . "\n\n";

// ────────────────────────────────────────────────────────────
//  7. PDO STORAGE (MySQL / Postgres / SQLite)
// ────────────────────────────────────────────────────────────

/*
$pdo = new PDO('sqlite:/tmp/jwt_test.db');
$pdoStorage = new PDOTokenStorage($pdo);
$pdoStorage->migrate(); // Creates tables on first run

$managerPdo = new JWTManager([
    'algorithm' => 'HS256',
    'secret'    => 'your-super-secret-key-at-least-32-chars!!',
], $pdoStorage);

$t = $managerPdo->issueTokens(1);
echo "PDO token subject: " . $managerPdo->validateAccessToken($t['access_token'])['sub'];
*/

// ────────────────────────────────────────────────────────────
//  8. MIDDLEWARE — PLAIN PHP (no framework)
// ────────────────────────────────────────────────────────────

/*
// At the top of any protected script:
$middleware = new JWTMiddleware($manager, [
    'token_source' => 'header',  // Bearer token from Authorization header
    'attribute'    => 'user',
]);

$payload = $middleware->authenticateOrExit(); // Dies with 401 JSON if invalid

echo "Hello, user " . $payload['sub'];
*/

// ────────────────────────────────────────────────────────────
//  9. MIDDLEWARE — PSR-15 (Slim 4, Mezzio, etc.)
// ────────────────────────────────────────────────────────────

/*
use Slim\Factory\AppFactory;

$app = AppFactory::create();

$app->add(new JWTMiddleware($manager, [
    'exclude' => ['/auth/login', '/auth/register', '/health'],
    'on_error' => function($request, $exception) use ($responseFactory) {
        $response = $responseFactory->createResponse(401);
        $response->getBody()->write(json_encode(['error' => $exception->getMessage()]));
        return $response->withHeader('Content-Type', 'application/json');
    },
]));

$app->get('/api/profile', function($request, $response) {
    $payload = $request->getAttribute('jwt_payload');
    $response->getBody()->write(json_encode(['user_id' => $payload['sub']]));
    return $response;
});

$app->run();
*/

// ────────────────────────────────────────────────────────────
// 10. TOKEN INSPECTION UTILITIES
// ────────────────────────────────────────────────────────────

$token = $tokens['access_token'];

echo "=== Token Inspection ===\n";
echo "Is valid:   " . ($manager->isValid($token) ? 'yes' : 'no') . "\n";
echo "Expires in: " . $manager->expiresIn($token) . " seconds\n";

$peeked = $manager->peek($token); // No signature check — for inspection only
echo "Subject:    " . $peeked['sub'] . "\n";
echo "JTI:        " . $peeked['jti'] . "\n";

// ────────────────────────────────────────────────────────────
// 11. KEY GENERATION HELPERS
// ────────────────────────────────────────────────────────────

echo "\n=== Generate Keys ===\n";
$hmacSecret = KeyGenerator::generateHmacSecret(64); // 512-bit
echo "HMAC secret: " . $hmacSecret . "\n";

$ecKeys = KeyGenerator::generateEcKeyPair('prime256v1'); // ES256
echo "EC private key length: " . strlen($ecKeys['private']) . " chars\n";

echo "\nAll examples complete.\n";
