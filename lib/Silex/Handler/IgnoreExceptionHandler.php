<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Handler;


use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

class IgnoreExceptionHandler implements OAuth2ExceptionHandlerInterface
{
    public function handle(AuthorizationException $e, Request $request, Application $app)
    {
        return null;
    }
}
