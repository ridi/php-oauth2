<?php
namespace Ridibooks\OAuth2Resource\Grant\DataTransferObject;

class ClientInfo
{
    /**
     * @var string
     */
    private $client_id;

    /**
     * @var string
     */
    private $client_secret;

    /**
     * @var string
     */
    private $scope;

    /**
     * @var string
     */
    private $redirect_uri;

    /**
     * ClientInfo constructor.
     * @param string $client_id
     * @param string $client_secret
     * @param string $scope
     * @param string $redirect_uri
     */
    public function __construct(
        string $client_id,
        string $client_secret,
        string $scope = null,
        string $redirect_uri = null
    ) {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->scope = $scope;
        $this->redirect_uri = $redirect_uri;
    }

    /**
     * @return string
     */
    public function getClientId(): string
    {
        return $this->client_id;
    }

    /**
     * @return string
     */
    public function getClientSecret(): string
    {
        return $this->client_secret;
    }

    /**
     * @return string
     */
    public function getScope(): string
    {
        return $this->scope;
    }

    /**
     * @return string
     */
    public function getRedirectUri(): string
    {
        return $this->redirect_uri;
    }

    /**
     * @return bool
     */
    public function isExistRedirectUri(): bool
    {
        return $this->redirect_uri !== null;
    }
}
