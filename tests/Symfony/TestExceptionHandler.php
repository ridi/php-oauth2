<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Symfony;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\InsufficientScopeException;
use Ridibooks\OAuth2\Symfony\Handler\OAuth2ExceptionHandlerInterface;
use Ridibooks\OAuth2\Symfony\Provider\OAuth2ServiceProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class TestExceptionHandler implements OAuth2ExceptionHandlerInterface
{
    /**
     * @param AuthorizationException $e
     * @param Request $request
     * @param OAuth2ServiceProvider $oauth2_service_provider
     * @return null|Response
     */
    public function handle(
        AuthorizationException $e,
        Request $request,
        OAuth2ServiceProvider $oauth2_service_provider
    ): ?Response {
        if ($e instanceof InsufficientScopeException) {
            return new Response('No sufficient scope.', Response::HTTP_FORBIDDEN);
        }

        return new Response('Login required.', Response::HTTP_UNAUTHORIZED);
    }
}
