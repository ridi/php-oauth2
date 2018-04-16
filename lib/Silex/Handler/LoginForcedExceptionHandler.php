<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Handler;


use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\InsufficientScopeException;
use Ridibooks\OAuth2\Grant\Grant;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Silex\Application;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

class LoginForcedExceptionHandler implements OAuth2ExceptionHandlerInterface
{
    public function handle(AuthorizationException $e, Request $request, Application $app)
    {
        /** @var Grant $grant */
        $grant = $app[OAuth2ProviderKeyConstant::GRANT];
        $state = \random_bytes(10);

        if ($e instanceof InsufficientScopeException) {
            $url = $grant->authorize($state, $request->getUri(), $e->getRequiredScopes());
        } else {
            $url = $grant->authorize($state, $request->getUri());
        }
        $response = RedirectResponse::create($url);
        $cookie = new Cookie('ridi.oauth2.state', $state, $request->getHost(), true, true);
        $response->headers->setCookie($cookie);
        return $response;
    }
}
