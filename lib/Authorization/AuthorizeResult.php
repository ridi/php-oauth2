<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization;

use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Grant\DataTransferObject\TokenData;

class AuthorizeResult
{
    /** @var JwtToken */
    private $jwt_token;

    /** @var bool */
    private $token_refreshed;

    /** @var TokenData */
    private $refreshed_token_data;

    private function __construct(JwtToken $jwt_token, bool $token_refreshed, ?TokenData $refreshed_token_data)
    {
        $this->jwt_token = $jwt_token;
        $this->token_refreshed = $token_refreshed;
        $this->refreshed_token_data = $refreshed_token_data;
    }

    /**
     * @param JwtToken $jwt_token
     * @return AuthorizeResult
     */
    public static function createForAuthorizedToken(JwtToken $jwt_token)
    {
        return new AuthorizeResult($jwt_token, false, null);
    }

    /**
     * @param JwtToken $jwt_token
     * @param TokenData $refreshed_token_data
     * @return AuthorizeResult
     */
    public static function createForRefreshedAndAuthorizedToken(JwtToken $jwt_token, TokenData $refreshed_token_data)
    {
        return new AuthorizeResult($jwt_token, true, $refreshed_token_data);
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
        return $this->token_refreshed;
    }

    /**
     * @return TokenData
     */
    public function getRefreshedTokenData(): TokenData
    {
        return $this->refreshed_token_data;
    }
}
