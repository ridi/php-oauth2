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
    private function generateState()
    {
        return \bin2hex(\random_bytes(8));
    }

    public function handle(AuthorizationException $e, Request $request, Application $app)
    {
        /** @var Grant $grant */
        $grant = $app[OAuth2ProviderKeyConstant::GRANT];
        $state = $this->generateState();

        if ($e instanceof InsufficientScopeException) {
            $url = $grant->authorize($state, $request->getUri(), $e->getRequiredScopes());
        } else {
            $url = $grant->authorize($state, $request->getUri());
        }
        $response = RedirectResponse::create($url);
        $cookie = new Cookie(OAuth2ProviderKeyConstant::STATE, $state, 0, $request->getHost(), true, true);
        $response->headers->setCookie($cookie);
        return $response;
    }
}
