<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization;

use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Grant\DataTransferObject\TokenData;

class AuthorizeResult
{
    /** @var JwtToken */
    private $jwt_token;

    /** @var TokenData */
    private $refreshed_token_data;

    private function __construct(JwtToken $jwt_token, ?TokenData $refreshed_token_data)
    {
        $this->jwt_token = $jwt_token;
        $this->refreshed_token_data = $refreshed_token_data;
    }

    /**
     * @param JwtToken $jwt_token
     * @return AuthorizeResult
     */
    public static function createFromAuthorizedToken(JwtToken $jwt_token)
    {
        return new AuthorizeResult($jwt_token, null);
    }

    /**
     * @param JwtToken $jwt_token
     * @param TokenData $refreshed_token_data
     * @return AuthorizeResult
     */
    public static function createFromRefreshedAndAuthorizedToken(JwtToken $jwt_token, TokenData $refreshed_token_data)
    {
        return new AuthorizeResult($jwt_token, $refreshed_token_data);
    }

    /**
     * @return JwtToken
     */
    public function getJwtToken(): JwtToken
    {
        return $this->jwt_token;
    }

    /**
     * @return bool
     */
    public function isTokenRefreshed(): bool
    {
        return ($this->refreshed_token_data !== null);
    }

    /**
     * @return TokenData
     */
    public function getRefreshedTokenData(): TokenData
    {
        return $this->refreshed_token_data;
    }
}
