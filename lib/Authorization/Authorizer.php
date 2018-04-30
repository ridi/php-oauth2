<?php declare(strict_types=1);


namespace Ridibooks\OAuth2\Authorization;


use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\InsufficientScopeException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Symfony\Component\HttpFoundation\Request;

class Authorizer
{
    /** @var JwtTokenValidator */
    private $token_validator;
    /** @var array */
    private $default_scopes;

    public function __construct(JwtTokenValidator $token_validator, array $default_scopes = [])
    {
        $this->token_validator = $token_validator;
        $this->default_scopes = $default_scopes;
    }

    /**
     * @param Request $request
     * @param array $required_scopes
     * @return JwtToken if the given request is authorized successfully
     * @throws AuthorizationException
     * @throws TokenNotFoundException if there is no access_token in the given request
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
