<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Handler;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\InsufficientScopeException;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class LoginRequiredExceptionHandler implements OAuth2ExceptionHandlerInterface
{
    public function handle(AuthorizationException $e, Request $request, Application $app): Response
    {
        if ($e instanceof InsufficientScopeException) {
            return Response::create('No sufficient scope', Response::HTTP_FORBIDDEN);
        }
        return Response::create('Login required', Response::HTTP_UNAUTHORIZED);
    }
}
