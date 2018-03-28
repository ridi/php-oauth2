<?php
namespace Ridibooks\OAuth2Resource\Client\DataTransferObject;


use InvalidArgumentException;

class TokenData {
    /**
     * @var Token
     */
    private $access_token;

    /**
     * @var string
     */
    private $token_type;

    /**
     * @var string
     */
    private $scope;

    /**
     * @var Token
     */
    private $refresh_token;

    /**
     * TokenData constructor.
     * @param Token $access_token
     * @param string $token_type
     * @param string $scope
     * @param Token $refresh_token
     */
    public function __construct(Token $access_token, string $token_type, string $scope, Token $refresh_token)
    {
        $this->access_token = $access_token;
        $this->token_type = $token_type;
        $this->scope = $scope;
        $this->refresh_token = $refresh_token;
    }

    /**
     * @return Token
     */
    public function getAccessToken(): Token
    {
        return $this->access_token;
    }

    /**
     * @return string
     */
    public function getTokenType(): string
    {
        return $this->token_type;
    }

    /**
     * @return string
     */
    public function getScope(): string
    {
        return $this->scope;
    }

    /**
     * @return Token
     */
    public function getRefreshToken(): Token
    {
        return $this->refresh_token;
    }

    public static function fromDict(array $dict)
    {
        if (in_array(
            null,
            array(
                $dict['access_token'],
                $dict['expires_in'],
                $dict['token_type'],
                $dict['scope'],
                $dict['refresh_token'],
                $dict['refresh_token_expires_in']
            ))) {
            throw new InvalidArgumentException();
        }

        $access_token = null;
        if (isset($dict['access_token'])) {
            $access_token = new Token($dict['access_token'], $dict['expires_in']);
        }

        $refresh_token = null;
        if (isset($dict['refresh_token'])) {
            $refresh_token = new Token($dict['refresh_token'], $dict['refresh_token_expires_in']);
        }

        return new TokenData($access_token, $dict['token_type'], $dict['scope'], $refresh_token);
    }
}