<?php declare(strict_types=1);

namespace Ridibooks\Silex\Provider;


use Ridibooks\OAuth2\Authorization\Validator\JwtInfo;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Authorization\Validator\ScopeChecker;
use Ridibooks\OAuth2\Grant\DataTransferObject\AuthorizationServerInfo;
use Ridibooks\OAuth2\Grant\DataTransferObject\ClientInfo;
use Ridibooks\OAuth2\Grant\Grant;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Silex\Application;
use Silex\ServiceProviderInterface;

class OAuth2ServiceProvider implements ServiceProviderInterface
{
    private $app;

    public function register(Application $app)
    {
        $this->app = $app;

        $client_id = $app[OAuth2ProviderKeyConstant::CLIENT_ID];
        $client_secret = $app[OAuth2ProviderKeyConstant::CLIENT_SECRET];
        $client_default_scope = $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_SCOPE] ?? [];
        $client_default_redirect_uri = $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_REDIRECT_URI] ?? null;

        $authorize_url = $app[OAuth2ProviderKeyConstant::AUTHORIZE_URL] ?? 'https://account.ridibooks.com/authorize';
        $token_url = $app[OAuth2ProviderKeyConstant::TOKEN_URL] ?? 'https://account.ridibooks.com/token';

        $jwt_algorithm = $app[OAuth2ProviderKeyConstant::JWT_ALGORITHM] ?? 'HS256';
        $jwt_secret = $app[OAuth2ProviderKeyConstant::JWT_SECRET] ?? 'secret';
        $jwt_expire_term = $app[OAuth2ProviderKeyConstant::JWT_EXPIRE_TERM] ?? JwtInfo::DEFAULT_EXPIRE_TERM;

        $client_info = new ClientInfo($client_id, $client_secret, $client_default_scope, $client_default_redirect_uri);
        $auth_server_info = new AuthorizationServerInfo($authorize_url, $token_url);
        $jwt_info = new JwtInfo($jwt_secret, $jwt_algorithm, $jwt_expire_term);

        // Initialize services
        $app[OAuth2ProviderKeyConstant::GRANT] = new Grant($client_info, $auth_server_info);
        $app[OAuth2ProviderKeyConstant::TOKEN_VALIDATOR] = new JwtTokenValidator($jwt_info);
        $app[OAuth2ProviderKeyConstant::SCOPE_CHECKER] = $scope_checker = new ScopeChecker();

        $app[OAuth2ProviderKeyConstant::MIDDLEWARE] = $app->share(function ($app) {
            return new OAuth2MiddlewareFactory($app);
        });
    }

    public function boot(Application $app)
    {
    }
}
