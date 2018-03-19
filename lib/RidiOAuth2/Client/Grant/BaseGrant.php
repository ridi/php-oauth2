<?php
namespace Ridibooks\OAuth2Resource\RidiOAuth2\Client\Grant;

use Ridibooks\OAuth2Resource\RidiOAuth2\Client\DataTransferObject\AuthorizationServerInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Client\DataTransferObject\ClientInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Client\DataTransferObject\TokenData;

abstract class BaseGrant
{
    /**
     * @var ClientInfo
     */
    protected $client_info;

    /**
     * @var AuthorizationServerInfo
     */
    protected $auth_server_info;

    /**
     * BaseGrant constructor.
     * @param ClientInfo $client_info
     * @param AuthorizationServerInfo $auth_server_info
     */
    public function __construct(ClientInfo $client_info, AuthorizationServerInfo $auth_server_info)
    {
        $this->client_info = $client_info;
        $this->auth_server_info = $auth_server_info;
    }

    /**
     * @return TokenData
     */
    public function getAccessToken(): TokenData
    {
        $data = $this->getRequestDataForAccessToken();

        $data['grant_type'] = $this->getGrantType();
        $data['client_id'] = $this->client_info->getClientId();
        $data['client_secret'] = $this->client_info->getClientSecret();

        if ($this->client_info->isExistScope()) {
            $data['scope'] = $this->client_info->getScope();
        }

        return TokenData::fromDict($this->request($this->auth_server_info->getTokenUrl(), $data));
    }

    /**
     * @return string
     */
    abstract protected function getGrantType(): string;

    /**
     * @return array
     */
    abstract protected function getRequestDataForAccessToken(): array;

    /**
     * @param string $url
     * @param array $data
     * @return array
     */
    protected function request(string $url, array $data): array
    {
        $headers = ['Accept: application/json'];

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10); // Conn timeout
        curl_setopt($ch, CURLOPT_TIMEOUT, 10); // Read timeout
        curl_setopt($ch, CURLOPT_HEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));

        // TODO: 개발이 완료 되면 해당 옵션 제거
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

        $body = curl_exec($ch);
        curl_close($ch);

        return json_decode($body);
    }
}