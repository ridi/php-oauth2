<?php
namespace Ridibooks\OAuth2Resource\RidiOAuth2\Client\Grant;

use Ridibooks\OAuth2Resource\RidiOAuth2\Client\Constant\OAuth2GrantType;
use Ridibooks\OAuth2Resource\RidiOAuth2\Client\DataTransferObject\AuthorizationServerInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Client\DataTransferObject\ClientInfo;

class RefreshTokenGrant extends BaseGrant
{
    private $refresh_token = null;

    public function __construct(
        ClientInfo $client_info,
        AuthorizationServerInfo $auth_server_info,
        string $refresh_token
    )
    {
        parent::__construct($client_info, $auth_server_info);
        $this->refresh_token = $refresh_token;
    }

    /**
     * @return array
     */
    public function getRequestDataForAccessToken(): array
    {
        return [
            'refresh_token' => $this->refresh_token,
        ];
    }

    /**
     * @return string
     */
    protected function getGrantType(): string
    {
        return OAuth2GrantType::REFRESH_TOKEN;
    }
}