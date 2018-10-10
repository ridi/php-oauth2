<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Provider;

use Ridibooks\OAuth2\Authorization\Authorizer;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Grant\DataTransferObject\AuthorizationServerInfo;
use Ridibooks\OAuth2\Grant\DataTransferObject\ClientInfo;
use Ridibooks\OAuth2\Grant\Granter;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Silex\Application;
use Silex\ServiceProviderInterface;

/**
 * Class OAuth2ServiceProvider
 *
 * OAuth2 Service Provider for Silex
 * @see https://silex.symfony.com/doc/1.3/providers.html
 *
 * @package Ridibooks\OAuth2\Silex\Provider
 *
 * **Example usage:**
 * ```php
 *      $app->register(new OAuth2ServiceProvider(), [
 *          OAuth2ProviderKeyConstant::CLIENT_ID => 'example-client-id',
 *          OAuth2ProviderKeyConstant::CLIENT_SECRET => 'example-client-secret',
 *          OAuth2ProviderKeyConstant::JWT_ALGORITHM => 'HS256',
 *          OAuth2ProviderKeyConstant::JWT_SECRET => 'example-secret'
 *      ]);
 *      ...
 *      $app->get('/auth-required', [$this, 'authRequiredApi'])
 *          ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(new LoginRequiredExceptionHandler(), new UserProvider());
 * ```
 *
 * **`OAuth2ServiceProvider` Options: @see OAuth2ProviderKeyConstant**
 *
 * - OAuth2ProviderKeyConstant::CLIENT_ID: (default = null)
 * - OAuth2ProviderKeyConstant::CLIENT_SECRET: (default = null)
 * - OAuth2ProviderKeyConstant::CLIENT_DEFAULT_SCOPE: (default = []) Default required scopes checked at middleware
 * - OAuth2ProviderKeyConstant::CLIENT_DEFAULT_REDIRECT_URI: (default = null)
 * - OAuth2ProviderKeyConstant::AUTHORIZE_URL: (default = https://account.ridibooks.com/oauth2/authorize/)
 * - OAuth2ProviderKeyConstant::TOKEN_URL: (default = https://account.ridibooks.com/oauth2/token/)
 * - OAuth2ProviderKeyConstant::USER_INFO_URL: (default = https://account.ridibooks.com/accounts/me/)
 * - OAuth2ProviderKeyConstant::JWT_ALGORITHM: (default = HS256)
 * - OAuth2ProviderKeyConstant::JWT_SECRET: (default = secret)
 * - OAuth2ProviderKeyConstant::JWT_EXPIRE_TERM: (default = 60 * 5 seconds)
 * - OAuth2ProviderKeyConstant::DEFAULT_EXCEPTION_HANDLER: (default = null) Default `OAuth2ExceptionHandlerInterface` implementation used by middleware
 * - OAuth2ProviderKeyConstant::DEFAULT_USER_PROVIDER: (default = DefaultUserProvider) Default `UserProviderInterface` implementation used by middleware
 *
 * **Built-in `OAuth2ExceptionHandlerInterface` Implementations:**
 *
 * - **`IgnoreExceptionHandler`**: Ignore all `AuthorizationException`
 * - **`LoginRequiredExceptionHandler`**: Handle `AuthorizationException` with `401 UNAUTHORIZED`, `403 FORBIDDEN` response
 * - **`LoginForcedExceptionHandler`**: Redirect `OAuth2ProviderKeyConstant::AUTHORIZE_URL` when `AuthorizationException` is occurred
 *
 * **Built-in `UserProviderInterface` Implementations:**
 *
 * - **`DefaultUserProvider`**: Get user information through specified URL request with access_token
 *
 * **`OAuth2ServiceProvider` Services:**
 *
 * - OAuth2ProviderKeyConstant::GRANTER @see Granter
 * - OAuth2ProviderKeyConstant::AUTHORIZER @see Authorizer
 * - OAuth2ProviderKeyConstant::MIDDLEWARE @see OAuth2MiddlewareFactory
 */
class OAuth2ServiceProvider implements ServiceProviderInterface
{
    private $app;

    public function register(Application $app)
    {
        $this->app = $app;

        // Initialize values
        $app[OAuth2ProviderKeyConstant::CLIENT_ID] = null;
        $app[OAuth2ProviderKeyConstant::CLIENT_SECRET] = null;
        $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_SCOPE] = [];
        $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_REDIRECT_URI] = null;

        $app[OAuth2ProviderKeyConstant::TOKEN_COOKIE_DOMAIN] = '.ridibooks.com';

        $app[OAuth2ProviderKeyConstant::AUTHORIZE_URL] = 'https://account.ridibooks.com/oauth2/authorize/';
        $app[OAuth2ProviderKeyConstant::TOKEN_URL] = 'https://account.ridibooks.com/oauth2/token/';
        $app[OAuth2ProviderKeyConstant::USER_INFO_URL] = 'https://account.ridibooks.com/accounts/me/';

        $app[OAuth2ProviderKeyConstant::JWT_ALGORITHM] = 'HS256';
        $app[OAuth2ProviderKeyConstant::JWT_SECRET] = 'secret';
        $app[OAuth2ProviderKeyConstant::JWT_EXPIRE_TERM] = 60 * 5;

        $app[OAuth2ProviderKeyConstant::DEFAULT_EXCEPTION_HANDLER] = null;
        $app[OAuth2ProviderKeyConstant::DEFAULT_USER_PROVIDER] = function ($app) {
            return new DefaultUserProvider($app[OAuth2ProviderKeyConstant::USER_INFO_URL]);
        };

        $app[OAuth2ProviderKeyConstant::USER] = null;
        $app[OAuth2ProviderKeyConstant::STATE] = null;

        // Initialize services
        $app[OAuth2ProviderKeyConstant::GRANTER] = function ($app) {
            $client_id = $app[OAuth2ProviderKeyConstant::CLIENT_ID];
            if (!$client_id) {
                return null;
            }
            $client_secret = $app[OAuth2ProviderKeyConstant::CLIENT_SECRET];
            $client_default_scope = $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_SCOPE];
            $client_default_redirect_uri = $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_REDIRECT_URI];

            $authorize_url = $app[OAuth2ProviderKeyConstant::AUTHORIZE_URL];
            $token_url = $app[OAuth2ProviderKeyConstant::TOKEN_URL];

            $client_info = new ClientInfo($client_id, $client_secret, $client_default_scope, $client_default_redirect_uri);
            $auth_server_info = new AuthorizationServerInfo($authorize_url, $token_url);

            return new Granter($client_info, $auth_server_info);
        };

        $app[OAuth2ProviderKeyConstant::AUTHORIZER] = function ($app) {
            $jwt_algorithm = $app[OAuth2ProviderKeyConstant::JWT_ALGORITHM];
            $jwt_secret = $app[OAuth2ProviderKeyConstant::JWT_SECRET];
            $jwt_expire_term = $app[OAuth2ProviderKeyConstant::JWT_EXPIRE_TERM];

            $jwt_token_validator = new JwtTokenValidator($jwt_secret, $jwt_algorithm, $jwt_expire_term);
            $granter = $app[OAuth2ProviderKeyConstant::GRANTER];
            $client_default_scope = $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_SCOPE];

            return new Authorizer($jwt_token_validator, $granter, $client_default_scope);
        };

        $app[OAuth2ProviderKeyConstant::MIDDLEWARE] = $app->share(function ($app) {
            return new OAuth2MiddlewareFactory($app);
        });
    }

    public function boot(Application $app)
    {
    }
}
