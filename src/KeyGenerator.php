<?php

declare(strict_types=1);

namespace AlfaCode\PhpJWT;

/**
 * Utility for generating keys and performing JWKS export.
 */
class KeyGenerator
{
    /**
     * Generate a cryptographically secure HMAC secret.
     *
     * @param int $bytes Length in bytes (256-bit = 32, 512-bit = 64)
     */
    public static function generateHmacSecret(int $bytes = 64): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /**
     * Generate an RSA key pair (PEM format).
     * Returns ['private' => '...', 'public' => '...']
     */
    public static function generateRsaKeyPair(int $bits = 4096): array
    {
        $config = [
            'digest_alg'       => 'sha256',
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        $res = openssl_pkey_new($config);
        if (!$res) {
            throw new \RuntimeException('RSA key generation failed: ' . openssl_error_string());
        }
        openssl_pkey_export($res, $private);
        $public = openssl_pkey_get_details($res)['key'];
        return ['private' => $private, 'public' => $public];
    }

    /**
     * Generate an EC key pair.
     * Curve: 'prime256v1' (P-256) for ES256, 'secp384r1' for ES384, 'secp521r1' for ES512.
     */
    public static function generateEcKeyPair(string $curve = 'prime256v1'): array
    {
        $config = [
            'digest_alg'       => 'sha256',
            'curve_name'       => $curve,
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ];
        $res = openssl_pkey_new($config);
        if (!$res) {
            throw new \RuntimeException('EC key generation failed: ' . openssl_error_string());
        }
        openssl_pkey_export($res, $private);
        $public = openssl_pkey_get_details($res)['key'];
        return ['private' => $private, 'public' => $public];
    }

    /**
     * Export a public key as a JWKS (JSON Web Key Set) representation.
     * Useful for publishing your public key to clients at /.well-known/jwks.json
     */
    public static function publicKeyToJwks(string $publicKeyPem, string $keyId = 'default', string $algorithm = 'RS256'): array
    {
        $key     = openssl_pkey_get_public($publicKeyPem);
        $details = openssl_pkey_get_details($key);

        if ($details['type'] === OPENSSL_KEYTYPE_RSA) {
            return [
                'keys' => [[
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => $algorithm,
                    'kid' => $keyId,
                    'n'   => self::base64UrlEncode($details['rsa']['n']),
                    'e'   => self::base64UrlEncode($details['rsa']['e']),
                ]],
            ];
        }

        if ($details['type'] === OPENSSL_KEYTYPE_EC) {
            $crv = match ($details['ec']['curve_name']) {
                'prime256v1' => 'P-256',
                'secp384r1'  => 'P-384',
                'secp521r1'  => 'P-521',
                default      => $details['ec']['curve_name'],
            };
            return [
                'keys' => [[
                    'kty' => 'EC',
                    'use' => 'sig',
                    'alg' => $algorithm,
                    'kid' => $keyId,
                    'crv' => $crv,
                    'x'   => self::base64UrlEncode($details['ec']['x']),
                    'y'   => self::base64UrlEncode($details['ec']['y']),
                ]],
            ];
        }

        throw new \RuntimeException('Unsupported key type for JWKS export.');
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
