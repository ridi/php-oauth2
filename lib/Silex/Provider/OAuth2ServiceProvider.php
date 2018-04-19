<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Provider;


use Ridibooks\OAuth2\Authorization\Validator\JwtInfo;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Authorization\Validator\ScopeChecker;
use Ridibooks\OAuth2\Grant\DataTransferObject\AuthorizationServerInfo;
use Ridibooks\OAuth2\Grant\DataTransferObject\ClientInfo;
use Ridibooks\OAuth2\Grant\Granter;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Silex\Application;
use Silex\ServiceProviderInterface;

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

        $app[OAuth2ProviderKeyConstant::AUTHORIZE_URL] = 'https://account.ridibooks.com/oauth2/authorize';
        $app[OAuth2ProviderKeyConstant::TOKEN_URL] = 'https://account.ridibooks.com/oauth2/token';

        $app[OAuth2ProviderKeyConstant::JWT_ALGORITHM] = 'HS256';
        $app[OAuth2ProviderKeyConstant::JWT_SECRET] = 'secret';
        $app[OAuth2ProviderKeyConstant::JWT_EXPIRE_TERM] = JwtInfo::DEFAULT_EXPIRE_TERM;

        $app[OAuth2ProviderKeyConstant::DEFAULT_EXCEPTION_HANDLER] = null;
        $app[OAuth2ProviderKeyConstant::DEFAULT_USER_PROVIDER] = null;

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

        $app[OAuth2ProviderKeyConstant::TOKEN_VALIDATOR] = function ($app) {
            $jwt_algorithm = $app[OAuth2ProviderKeyConstant::JWT_ALGORITHM];
            $jwt_secret = $app[OAuth2ProviderKeyConstant::JWT_SECRET];
            $jwt_expire_term = $app[OAuth2ProviderKeyConstant::JWT_EXPIRE_TERM];

            $jwt_info = new JwtInfo($jwt_secret, $jwt_algorithm, $jwt_expire_term);

            return new JwtTokenValidator($jwt_info);
        };

        $app[OAuth2ProviderKeyConstant::MIDDLEWARE] = $app->share(function ($app) {
            return new OAuth2MiddlewareFactory($app);
        });
    }

    public function boot(Application $app)
    {
    }
}
