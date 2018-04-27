<?php declare(strict_types=1);


namespace Ridibooks\OAuth2\Authorization;


use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\InsufficientScopeException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Validator\JwtInfo;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Symfony\Component\HttpFoundation\Request;

class Authorizer
{
    /** @var JwtTokenValidator */
    private $token_validator;
    /** @var array */
    private $default_scopes;

    public function __construct($app)
    {
        $jwt_algorithm = $app[OAuth2ProviderKeyConstant::JWT_ALGORITHM];
        $jwt_secret = $app[OAuth2ProviderKeyConstant::JWT_SECRET];
        $jwt_expire_term = $app[OAuth2ProviderKeyConstant::JWT_EXPIRE_TERM];

        $jwt_info = new JwtInfo($jwt_secret, $jwt_algorithm, $jwt_expire_term);

        $this->token_validator = new JwtTokenValidator($jwt_info);
        $this->default_scopes = $app[OAuth2ProviderKeyConstant::CLIENT_DEFAULT_SCOPE];
    }

    /**
     * @param Request $request
     * @param array $required_scopes
     * @return JwtToken if the given request is authorized successfully
     * @throws AuthorizationException
     * @throws InsufficientScopeException
     */
    public function authorize(Request $request, array $required_scopes = []): JwtToken
    {
        $access_token = $request->cookies->get(AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY);
        // 1. Validate access_token
        $token = $this->token_validator->validateToken($access_token);
        // 2. Check scope
        if (empty($required_scopes)) {
            $required_scopes = $this->default_scopes;
        }
        if (!empty($required_scopes) && !$token->hasScopes($required_scopes)) {
            throw new InsufficientScopeException($required_scopes);
        }

        return $token;
    }
}
