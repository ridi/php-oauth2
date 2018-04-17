<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Silex\Provider;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\InsufficientScopeException;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Authorization\Validator\ScopeChecker;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Ridibooks\OAuth2\Grant\Grant;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Ridibooks\OAuth2\Silex\Handler\OAuth2ExceptionHandlerInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

class OAuth2MiddlewareFactory
{
    /** @var Grant */
    private $grant;
    /** @var JwtTokenValidator */
    private $token_validator;
    /** @var ScopeChecker */
    private $scope_checker;
    /** @var OAuth2ExceptionHandlerInterface */
    private $default_exception_handler;
    /** @var UserProviderInterface */
    private $default_user_provider;
    /** @var array */
    private $default_scopes;

    public function __construct($app)
    {
        $this->grant = $app[OAuth2ProviderKeyConstant::GRANT];
        $this->token_validator = $app[OAuth2ProviderKeyConstant::TOKEN_VALIDATOR];
        $this->scope_checker = $app[OAuth2ProviderKeyConstant::SCOPE_CHECKER];
        $this->default_scopes = $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_SCOPE];
        $this->default_exception_handler = $app[OAuth2ProviderKeyConstant::DEFAULT_EXCEPTION_HANDLER];
        $this->default_user_provider = $app[OAuth2ProviderKeyConstant::DEFAULT_USER_PROVIDER];
    }

    public function authorize(array $required_scopes = [], OAuth2ExceptionHandlerInterface $exception_handler = null, UserProviderInterface $user_provider = null)
    {
        if ($exception_handler === null) {
            $exception_handler = $this->default_exception_handler;
        }
        if ($user_provider === null) {
            $user_provider = $this->default_user_provider;
        }
        if (empty($required_scopes)) {
            $required_scopes = $this->default_scopes;
        }
        return function (Request $request, Application $app) use ($required_scopes, $exception_handler, $user_provider) {
            try {
                $access_token = $request->cookies->get(AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY);
                // 1. Validate access_token
                $token = $this->token_validator->validateToken($access_token);
                // 2. Check scope
                if (!empty($required_scopes) && !$token->hasScopes($required_scopes)) {
                    throw new InsufficientScopeException($required_scopes);
                }
                // 3. Load user
                if (isset($user_provider)) {
                    $user = $user_provider->getUser($token);
                    $app[OAuth2ProviderKeyConstant::USER] = $user;
                }
            } catch (AuthorizationException $e) {
                return $exception_handler->handle($e, $request, $app);
            }
        };
    }
}
