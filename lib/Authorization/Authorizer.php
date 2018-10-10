<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization;

use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InsufficientScopeException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Grant\Granter;

class Authorizer
{
    /** @var JwtTokenValidator */
    private $token_validator;
    /** @var Granter */
    private $granter;
    /** @var array */
    private $default_scopes;

    public function __construct(JwtTokenValidator $token_validator, Granter $granter, array $default_scopes = [])
    {
        $this->token_validator = $token_validator;
        $this->granter = $granter;
        $this->default_scopes = $default_scopes;
    }

    public function authorize(
        ?string $access_token,
        ?string $refresh_token,
        array $required_scopes = [],
        bool $use_refreshing_access_token = false
    ): AuthorizeResult {
        // 1. Validate access_token
        try {
            $token = $this->token_validator->validateToken($access_token);
            $authorize_result = AuthorizeResult::createFromAuthorizedToken($token);
        } catch (TokenNotFoundException | ExpiredTokenException $e) {
            // Refresh access token if requested
            if ($use_refreshing_access_token && !empty($refresh_token)) {
                $token_data = $this->granter->refresh($refresh_token);
                $token = $this->token_validator->validateToken($token_data->getAccessToken()->getToken());

                $authorize_result = AuthorizeResult::createFromRefreshedAndAuthorizedToken($token, $token_data);
            } else {
                throw $e;
            }
        }

        // 2. Check scope
        if (empty($required_scopes)) {
            $required_scopes = $this->default_scopes;
        }
        if (!empty($required_scopes) && !$authorize_result->getJwtToken()->hasScopes($required_scopes)) {
            throw new InsufficientScopeException($required_scopes);
        }

        return $authorize_result;
    }
}
