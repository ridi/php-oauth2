<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Provider;

use Ridibooks\OAuth2\Authorization\Authorizer;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Ridibooks\OAuth2\Silex\Handler\OAuth2ExceptionHandlerInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

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

    public function authorize(array $required_scopes = [], OAuth2ExceptionHandlerInterface $exception_handler = null, UserProviderInterface $user_provider = null)
    {
        if ($exception_handler === null) {
            $exception_handler = $this->default_exception_handler;
        }
        if ($user_provider === null) {
            $user_provider = $this->default_user_provider;
        }
        return function (Request $request, Application $app) use ($required_scopes, $exception_handler, $user_provider) {
            try {
                $token = $this->authorizer->authorize($request, $required_scopes);

                if (isset($user_provider)) {
                    $user = $user_provider->getUser($token, $request, $app);
                    $app[OAuth2ProviderKeyConstant::USER] = $user;
                }
            } catch (AuthorizationException $e) {
                return $exception_handler->handle($e, $request, $app);
            }

            return null;
        };
    }
}
