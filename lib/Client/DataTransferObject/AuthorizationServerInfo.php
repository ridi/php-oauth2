<?php
namespace Ridibooks\OAuth2Resource\Client\DataTransferObject;


class AuthorizationServerInfo {
    /**
     * @var string
     */
    private $authorization_url;

    /**
     * @var string
     */
    private $token_url;

    /**
     * AuthorizationServerInfo constructor.
     * @param string $authorization_url
     * @param string $token_url
     */
    public function __construct(string $authorization_url, string $token_url)
    {
        $this->authorization_url = $authorization_url;
        $this->token_url = $token_url;
    }

    /**
     * @return string
     */
    public function getAuthorizationUrl(): string
    {
        return $this->authorization_url;
    }

    /**
     * @return string
     */
    public function getTokenUrl(): string
    {
        return $this->token_url;
    }
}