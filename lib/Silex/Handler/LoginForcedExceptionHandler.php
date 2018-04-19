<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Handler;


use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\InsufficientScopeException;
use Ridibooks\OAuth2\Grant\Granter;
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
        /** @var Granter $granter */
        $granter = $app[OAuth2ProviderKeyConstant::GRANTER];
        $redirect_uri = $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_REDIRECT_URI] ?: $request->getUri();
        $state = $this->generateState();

        if ($e instanceof InsufficientScopeException) {
            $url = $granter->authorize($state, $redirect_uri, $e->getRequiredScopes());
        } else {
            $url = $granter->authorize($state, $redirect_uri);
        }
        $response = RedirectResponse::create($url);
        $cookie = new Cookie(OAuth2ProviderKeyConstant::STATE, $state, 0, $request->getHost(), true, true);
        $response->headers->setCookie($cookie);
        return $response;
    }
}
