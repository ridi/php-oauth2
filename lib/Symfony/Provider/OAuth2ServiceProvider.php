<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2\Symfony\Provider;

use Doctrine\Common\Annotations\CachedReader;
use Ridibooks\OAuth2\Authorization\Authorizer;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Grant\DataTransferObject\AuthorizationServerInfo;
use Ridibooks\OAuth2\Grant\DataTransferObject\ClientInfo;
use Ridibooks\OAuth2\Grant\Granter;
use Ridibooks\OAuth2\Symfony\Subscriber\OAuth2Middleware;
use Symfony\Component\EventDispatcher\EventDispatcher;

class OAuth2ServiceProvider
{
    /** @var CachedReader */
    private $annotation_reader;

    /** @var EventDispatcher */
    private $event_dispatcher;

    /** @var array */
    private $configs;

    /** @var Granter */
    private $granter;

    /** @var Authorizer */
    private $authorizer;

    /** @var OAuth2Middleware */
    private $middleware;

    /**
     * @param CachedReader $annotation_reader
     * @param EventDispatcher $event_dispatcher
     * @param array $configs
     */
    public function __construct(CachedReader $annotation_reader, EventDispatcher $event_dispatcher, array $configs)
    {
        $this->annotation_reader = $annotation_reader;
        $this->event_dispatcher = $event_dispatcher;
        $this->configs = $configs;

        $this->setGranter();
        $this->setAuthorizer();
        $this->setMiddleware();
    }

    /**
     * @return array
     */
    public function getConfigs(): array
    {
        return $this->configs;
    }

    /**
     * @return Granter
     */
    public function getGranter(): Granter
    {
        return $this->granter;
    }

    /**
     * @return Authorizer
     */
    public function getAuthorizer(): Authorizer
    {
        return $this->authorizer;
    }

    /**
     * @return OAuth2Middleware
     */
    public function getMiddleware(): OAuth2Middleware
    {
        return $this->middleware;
    }

    private function setGranter(): void
    {
        $client_info = new ClientInfo($this->configs['client_id'], $this->configs['client_secret']);
        $auth_server_info = new AuthorizationServerInfo(
            $this->configs['authorize_url'],
            $this->configs['token_url']
        );
        $this->granter = new Granter($client_info, $auth_server_info);
    }

    private function setAuthorizer(): void
    {
        $jwt_token_validator = JwtTokenValidator::create();
        if (!empty($this->configs['jwt_keys'])) {
            foreach($this->configs['jwt_keys'] as $key_info) {
                if (isset($key_info['secret'])) {
                    $jwt_token_validator->addKey($key_info['kid'], $key_info['secret'], $key_info['algorithm']);
                } elseif (isset($key_info['file_path'])) {
                    $jwt_token_validator->addKeyFromFile($key_info['kid'], $key_info['file_path'], $key_info['algorithm']);
                }
            }
        }

        if (!isset($this->configs['jwt_expire_term'])) {
            $jwt_token_validator->setExpireTerm($this->configs['jwt_expire_term']);
        }

        $this->authorizer = new Authorizer($jwt_token_validator, $this->configs['client_default_scope']);
    }

    private function setMiddleware()
    {
        $this->middleware = new OAuth2Middleware($this->annotation_reader, $this);
        $this->event_dispatcher->addSubscriber($this->middleware);
    }
}
