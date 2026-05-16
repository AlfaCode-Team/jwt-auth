<?php

declare(strict_types=1);

namespace AlfaCode\PhpJWT\Middleware;

use AlfaCode\PhpJWT\JWTManager;
use AlfaCode\PhpJWT\Exceptions\JWTException;

/**
 * PSR-15 compatible JWT authentication middleware.
 *
 * Usage with any PSR-15 compatible framework (Slim, Mezzio, etc.):
 *
 *   $app->add(new JWTMiddleware($manager, [
 *       'attribute'    => 'jwt_payload',     // request attribute name
 *       'exclude'      => ['/auth/login', '/auth/register'],
 *       'token_source' => 'header',          // 'header' | 'cookie' | 'query'
 *       'cookie_name'  => 'access_token',
 *       'query_param'  => 'token',
 *       'on_error'     => null,              // callable($request, $exception): ResponseInterface
 *   ]));
 */
class JWTMiddleware
{
    private JWTManager $manager;
    private array $options;

    public function __construct(JWTManager $manager, array $options = [])
    {
        $this->manager = $manager;
        $this->options = array_merge([
            'attribute'    => 'jwt_payload',
            'exclude'      => [],
            'token_source' => 'header',
            'cookie_name'  => 'access_token',
            'query_param'  => 'token',
            'on_error'     => null,
        ], $options);
    }

    /**
     * PSR-15 process() method.
     * Accepts Psr\Http\Message\ServerRequestInterface and Psr\Http\Server\RequestHandlerInterface.
     */
    public function process($request, $handler)
    {
        $path = $request->getUri()->getPath();

        // Allow excluded paths through without auth
        foreach ($this->options['exclude'] as $pattern) {
            if ($this->matchPath($pattern, $path)) {
                return $handler->handle($request);
            }
        }

        try {
            $token   = $this->extractToken($request);
            $payload = $this->manager->validateAccessToken($token);

            // Attach payload to request for downstream handlers
            $request = $request->withAttribute($this->options['attribute'], $payload);
        } catch (JWTException $e) {
            if (is_callable($this->options['on_error'])) {
                return ($this->options['on_error'])($request, $e);
            }
            return $this->defaultErrorResponse($e);
        }

        return $handler->handle($request);
    }

    // ──────────────────────────────────────────────
    // Plain PHP usage (non-PSR)
    // ──────────────────────────────────────────────

    /**
     * Authenticate using PHP super-globals.
     * Call this at the top of any script or controller that requires auth.
     *
     * Returns the decoded payload or sends a 401 and exits.
     */
    public function authenticateOrExit(): array
    {
        $token = $this->extractTokenFromGlobals();

        try {
            return $this->manager->validateAccessToken($token);
        } catch (JWTException $e) {
            http_response_code(401);
            header('Content-Type: application/json');
            echo json_encode(['error' => $e->getMessage()]);
            exit;
        }
    }

    /**
     * Attempt to extract the token from $_SERVER / $_COOKIE / $_GET.
     * Returns null on failure (non-fatal variant for optional auth).
     */
    public function tryAuthenticate(): ?array
    {
        try {
            $token = $this->extractTokenFromGlobals();
            return $this->manager->validateAccessToken($token);
        } catch (\Throwable) {
            return null;
        }
    }

    // ──────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────

    private function extractToken(object $request): string
    {
        return match ($this->options['token_source']) {
            'cookie' => $this->extractFromCookiePsr($request),
            'query'  => $this->extractFromQueryPsr($request),
            default  => $this->extractFromHeaderPsr($request),
        };
    }

    private function extractFromHeaderPsr(object $request): string
    {
        $header = $request->getHeaderLine('Authorization');
        if (!$header) {
            throw new \PhpJWT\Exceptions\JWTException('No Authorization header found.');
        }
        if (!preg_match('/Bearer\s+(.+)/i', $header, $m)) {
            throw new \PhpJWT\Exceptions\JWTException('Malformed Authorization header.');
        }
        return $m[1];
    }

    private function extractFromCookiePsr(object $request): string
    {
        $cookies = $request->getCookieParams();
        $name    = $this->options['cookie_name'];
        if (empty($cookies[$name])) {
            throw new \PhpJWT\Exceptions\JWTException("Cookie '{$name}' not found.");
        }
        return $cookies[$name];
    }

    private function extractFromQueryPsr(object $request): string
    {
        $params = $request->getQueryParams();
        $param  = $this->options['query_param'];
        if (empty($params[$param])) {
            throw new \PhpJWT\Exceptions\JWTException("Query param '{$param}' not found.");
        }
        return $params[$param];
    }

    private function extractTokenFromGlobals(): string
    {
        $source = $this->options['token_source'];

        if ($source === 'cookie') {
            $name = $this->options['cookie_name'];
            if (!empty($_COOKIE[$name])) {
                return $_COOKIE[$name];
            }
            throw new \PhpJWT\Exceptions\JWTException("Cookie '{$name}' not found.");
        }

        if ($source === 'query') {
            $param = $this->options['query_param'];
            if (!empty($_GET[$param])) {
                return $_GET[$param];
            }
            throw new \PhpJWT\Exceptions\JWTException("Query param '{$param}' not found.");
        }

        // Default: Authorization header
        $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (!$header) {
            throw new \PhpJWT\Exceptions\JWTException('No Authorization header found.');
        }
        if (!preg_match('/Bearer\s+(.+)/i', $header, $m)) {
            throw new \PhpJWT\Exceptions\JWTException('Malformed Authorization header.');
        }
        return $m[1];
    }

    private function matchPath(string $pattern, string $path): bool
    {
        if ($pattern === $path) {
            return true;
        }
        // Support wildcards: /auth/*
        $regex = '#^' . str_replace('\*', '.*', preg_quote($pattern, '#')) . '$#';
        return (bool) preg_match($regex, $path);
    }

    private function defaultErrorResponse(JWTException $e): object
    {
        // Returns a minimal PSR-7-like object.
        // In practice, your framework will provide a real ResponseInterface factory.
        // This is used when no on_error callback is supplied.

        // If using plain PHP, just output JSON and exit
        if (!headers_sent()) {
            header('HTTP/1.1 401 Unauthorized');
            header('Content-Type: application/json');
        }

        // Return a simple object that frameworks can handle
        return new class($e->getMessage()) {
            public int $status = 401;
            public string $body;
            public function __construct(string $msg) {
                $this->body = json_encode(['error' => 'Unauthorized', 'message' => $msg]);
            }
            public function getStatusCode(): int { return $this->status; }
            public function getBody(): string { return $this->body; }
        };
    }
}
