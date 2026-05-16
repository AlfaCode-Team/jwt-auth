# PHP JWT Auth

A standalone, production-grade JWT authentication library for PHP 8.1+. Zero framework dependencies. More powerful and flexible than Laravel Passport for non-Laravel use.

---

## Why not Laravel Passport?

| Feature | Laravel Passport | PHP JWT Auth |
|---|---|---|
| Framework dependency | Laravel required | **None — pure PHP** |
| OAuth2 overhead | Full OAuth2 server | Lightweight JWT only |
| Algorithm support | RS256 only | **HS256/384/512, RS256/384/512, ES256/384/512** |
| Storage backends | MySQL only | **Redis, PDO (any DB), File, custom** |
| Refresh token rotation | Limited | **Full rotation + single-use enforcement** |
| JWKS export | No | **Yes** |
| PSR-15 middleware | Laravel-specific | **Any PSR-15 framework + plain PHP** |
| Token introspection | No | **Yes (`peek`, `isValid`, `expiresIn`)** |

---

## Installation

```bash
composer require yourname/php-jwt-auth
```

Or clone and include the autoloader:

```php
require __DIR__ . '/vendor/autoload.php';
```

---

## Quick Start

```php
use PhpJWT\JWTManager;

$manager = new JWTManager([
    'algorithm'  => 'HS256',
    'secret'     => 'your-secret-at-least-32-chars-long!!',
    'access_ttl' => 900,     // 15 minutes
    'refresh_ttl'=> 604800,  // 7 days
    'issuer'     => 'https://api.example.com',
]);

// Issue tokens (e.g. on login)
$tokens = $manager->issueTokens($userId, [
    'email' => $user->email,
    'roles' => $user->roles,
]);

// Returns:
// [
//   'token_type'    => 'Bearer',
//   'access_token'  => 'eyJ...',
//   'refresh_token' => 'eyJ...',
//   'expires_in'    => 900,
// ]

// Validate on each API request
$payload = $manager->validateAccessToken($tokens['access_token']);
echo $payload['sub'];   // user ID
echo $payload['email']; // custom claim

// Refresh when expired
$newTokens = $manager->refresh($tokens['refresh_token']);

// Logout (revoke)
$manager->revokeAccessToken($tokens['access_token']);
$manager->revokeAllForSubject($userId); // logout all devices
```

---

## Configuration Reference

```php
$manager = new JWTManager([
    // Algorithm: HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512
    'algorithm'          => 'HS256',

    // HMAC secret (required for HS*). Min 32 chars.
    'secret'             => 'your-secret',

    // RSA/EC keys (required for RS*/ES*)
    'private_key'        => file_get_contents('/etc/jwt/private.pem'),
    'public_key'         => file_get_contents('/etc/jwt/public.pem'),

    // Token lifetimes in seconds
    'access_ttl'         => 900,     // 15 min
    'refresh_ttl'        => 604800,  // 7 days

    // Standard claims
    'issuer'             => 'https://api.example.com',
    'audience'           => ['https://app.example.com'],

    // Clock skew tolerance in seconds
    'leeway'             => 30,

    // Enable JTI blacklisting (requires storage)
    'blacklist_enabled'  => true,

    // Issue a new refresh token on each use
    'refresh_rotation'   => true,

    // Revoke old refresh token on rotation
    'single_use_refresh' => true,
]);
```

---

## Storage Backends

### Redis (recommended for production)

```php
use PhpJWT\Storage\RedisTokenStorage;

$redis   = new Redis();
$redis->connect('127.0.0.1', 6379);

$storage = new RedisTokenStorage($redis, 'myapp'); // prefix optional
$manager = new JWTManager($config, $storage);
```

### PDO — MySQL, PostgreSQL, SQLite

```php
use PhpJWT\Storage\PDOTokenStorage;

$pdo     = new PDO('mysql:host=localhost;dbname=myapp', 'user', 'pass');
$storage = new PDOTokenStorage($pdo);
$storage->migrate(); // Creates tables. Run once.

$manager = new JWTManager($config, $storage);

// Clean up expired entries (add to cron):
$storage->purgeExpired();
```

### File (zero-dependency, dev/testing)

```php
use PhpJWT\Storage\FileTokenStorage;

$storage = new FileTokenStorage(__DIR__ . '/storage/jwt');
$manager = new JWTManager($config, $storage);
```

---

## Asymmetric Keys (RS256 / ES256)

```php
use PhpJWT\KeyGenerator;

// One-time: generate and save keys
$rsaKeys = KeyGenerator::generateRsaKeyPair(4096);
file_put_contents('/etc/jwt/private.pem', $rsaKeys['private']);
file_put_contents('/etc/jwt/public.pem',  $rsaKeys['public']);

// Use
$manager = new JWTManager([
    'algorithm'   => 'RS256',
    'private_key' => file_get_contents('/etc/jwt/private.pem'),
    'public_key'  => file_get_contents('/etc/jwt/public.pem'),
]);

// Publish JWKS for clients (e.g. at /.well-known/jwks.json)
$jwks = KeyGenerator::publicKeyToJwks($rsaKeys['public'], 'key-2024', 'RS256');
echo json_encode($jwks);

// EC (ES256) — smaller keys, same security as RS256 2048-bit
$ecKeys = KeyGenerator::generateEcKeyPair('prime256v1');
```

---

## Middleware

### Plain PHP

```php
use PhpJWT\Middleware\JWTMiddleware;

$mw = new JWTMiddleware($manager);

// Blocks request with 401 JSON if token is missing/invalid
$payload = $mw->authenticateOrExit();

// Or optional auth (null if not authenticated)
$payload = $mw->tryAuthenticate();
```

### PSR-15 (Slim 4, Mezzio, etc.)

```php
$app->add(new JWTMiddleware($manager, [
    'exclude'      => ['/auth/login', '/auth/register'],
    'attribute'    => 'jwt_payload',   // set on the Request object
    'token_source' => 'header',        // 'header' | 'cookie' | 'query'
    'on_error'     => function($request, $e) use ($responseFactory) {
        $res = $responseFactory->createResponse(401);
        $res->getBody()->write(json_encode(['error' => $e->getMessage()]));
        return $res->withHeader('Content-Type', 'application/json');
    },
]));

// In your route handler:
$app->get('/me', function($req, $res) {
    $user = $req->getAttribute('jwt_payload');
    $res->getBody()->write(json_encode(['id' => $user['sub']]));
    return $res;
});
```

---

## Fluent Token Builder

For fine-grained control over the exact payload:

```php
use PhpJWT\Token\{JWT, TokenBuilder};

$jwt   = new JWT('HS512');
$token = (new TokenBuilder())
    ->issuedBy('https://api.example.com')
    ->permittedFor(['https://app.example.com'])
    ->relatedTo($userId)
    ->identifiedBy(bin2hex(random_bytes(16)))
    ->expiresAfter(3600)
    ->canOnlyBeUsedAfter(time() + 30)
    ->withClaim('scope', 'read:posts write:posts')
    ->withClaim('plan', 'premium')
    ->build($jwt, $secret);
```

---

## Token Inspection

```php
$manager->isValid($token);        // bool
$manager->expiresIn($token);      // int seconds (negative if expired)
$manager->peek($token);           // array payload (NO signature check!)
```

---

## Running Tests

```bash
composer install
./vendor/bin/phpunit tests/
```

---

## Key Generation CLI

```bash
# Generate an HMAC secret
php -r "echo bin2hex(random_bytes(64)) . PHP_EOL;"

# Generate RSA key pair
openssl genrsa -out private.pem 4096
openssl rsa -in private.pem -pubout -out public.pem

# Generate EC key pair (P-256)
openssl ecparam -name prime256v1 -genkey -noout -out ec-private.pem
openssl ec -in ec-private.pem -pubout -out ec-public.pem
```

---

## Security Best Practices

- Use a secret **≥ 64 bytes** for HMAC (use `KeyGenerator::generateHmacSecret()`).
- Prefer **RS256 or ES256** for multi-service architectures (services only need the public key).
- Keep `access_ttl` **short** (5–15 min). Refresh tokens carry the long-lived trust.
- Enable **`refresh_rotation`** + **`single_use_refresh`** to detect refresh token theft.
- Use **Redis** or a database for production storage; file storage is for development only.
- Always validate the `aud` claim when a token can be presented to multiple services.
- Set a meaningful `leeway` (e.g. 30s) only if you have distributed systems with clock drift.

---

## License

MIT
