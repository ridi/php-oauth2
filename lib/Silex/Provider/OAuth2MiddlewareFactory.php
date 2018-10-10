<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Silex\Provider;

use Ridibooks\OAuth2\Authorization\Authorizer;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Ridibooks\OAuth2\Grant\DataTransferObject\TokenData;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Ridibooks\OAuth2\Silex\Handler\OAuth2ExceptionHandlerInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class OAuth2MiddlewareFactory
{
    /** @var Authorizer */
    private $authorizer;
    /** @var OAuth2ExceptionHandlerInterface */
    private $default_exception_handler;
    /** @var UserProviderInterface */
    private $default_user_provider;

    public function __construct($app)
    {
        $this->authorizer = $app[OAuth2ProviderKeyConstant::AUTHORIZER];
        $this->default_exception_handler = $app[OAuth2ProviderKeyConstant::DEFAULT_EXCEPTION_HANDLER];
        $this->default_user_provider = $app[OAuth2ProviderKeyConstant::DEFAULT_USER_PROVIDER];
    }

    public function authorize(
        array $required_scopes = [],
        OAuth2ExceptionHandlerInterface $exception_handler = null,
        UserProviderInterface $user_provider = null,
        $use_refreshing_access_token = false
    ) {
        if ($exception_handler === null) {
            $exception_handler = $this->default_exception_handler;
        }
        if ($user_provider === null) {
            $user_provider = $this->default_user_provider;
        }
        return function (Request $request, Application $app) use ($required_scopes, $exception_handler, $user_provider, $use_refreshing_access_token) {
            try {
                $access_token = $request->cookies->get(AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY);
                $refresh_token = $request->cookies->get(AccessTokenConstant::REFRESH_TOKEN_COOKIE_KEY);

                $authorize_result = $this->authorizer->authorize($access_token, $refresh_token, $required_scopes, $use_refreshing_access_token);
                if ($authorize_result->isTokenRefreshed()) {
                    $app->after($this->setTokenCookiesMiddleware($authorize_result->getRefreshedTokenData()));
                }

                if (isset($user_provider)) {
                    $user = $user_provider->getUser($authorize_result->getJwtToken(), $request, $app);
                    $app[OAuth2ProviderKeyConstant::USER] = $user;
                }
            } catch (AuthorizationException $e) {
                return $exception_handler->handle($e, $request, $app);
            }

            return null;
        };
    }

    /**
     * Set-Cookie Middleware: access token(ridi-at), refresh token(ridi-rt)
     *
     * @param TokenData $token_data
     * @return \Closure
     */
    private function setTokenCookiesMiddleware(TokenData $token_data)
    {
        return function (Request $request, Response $response, Application $app) use ($token_data) {
            $access_token_cookie = new Cookie(
                AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY,
                $token_data->getAccessToken()->getToken(),
                time() + $token_data->getAccessToken()->getExpiresIn(),
                '/',
                $app[OAuth2ProviderKeyConstant::TOKEN_COOKIE_DOMAIN],
                true,
                true
            );
            $response->headers->setCookie($access_token_cookie);

            $refresh_token_cookie = new Cookie(
                AccessTokenConstant::REFRESH_TOKEN_COOKIE_KEY,
                $token_data->getRefreshToken()->getToken(),
                time() + $token_data->getRefreshToken()->getExpiresIn(),
                '/',
                $app[OAuth2ProviderKeyConstant::TOKEN_COOKIE_DOMAIN],
                true,
                true
            );
            $response->headers->setCookie($refresh_token_cookie);
        };
    }
}
