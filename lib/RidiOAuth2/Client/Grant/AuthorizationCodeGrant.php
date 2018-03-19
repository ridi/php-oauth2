<?php
namespace Ridibooks\OAuth2Resource\RidiOAuth2\Client\Grant;

use Ridibooks\OAuth2Resource\RidiOAuth2\Client\Constant\OAuth2GrantType;
use Ridibooks\OAuth2Resource\RidiOAuth2\Client\DataTransferObject\AuthorizationServerInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Client\DataTransferObject\ClientInfo;

class AuthorizationCodeGrant extends BaseGrant
{
    private $code = null;

    public function __construct(ClientInfo $client_info, AuthorizationServerInfo $auth_server_info, string $code)
    {
        parent::__construct($client_info, $auth_server_info);
        $this->code = $code;
    }

    /**
     * @param string $state
     * @return string
     */
    public function getAuthorizationUrl(string $state): string
    {
        $query = http_build_query([
            'client_id' => $this->client_info->getClientId(),
            'redirect_uri' => $this->client_info->getRedirectUri(),
            'scope' => $this->client_info->getScope(),
            'state' => $state,
            'response_type' => 'code',
        ]);

        $authorize_url = $this->auth_server_info->getAuthorizationUrl() . '?' . $query;
        return $authorize_url;
    }


    /**
     * @return array
     */
    public function getRequestDataForAccessToken(): array
    {
        return [
            'code' => $this->code,
        ];
    }

    /**
     * @return string
     */
    protected function getGrantType(): string
    {
        return OAuth2GrantType::AUTHORIZATION_CODE;
    }
}