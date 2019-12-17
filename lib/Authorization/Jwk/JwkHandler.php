<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Jwk;

use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredConstantException;
use Ridibooks\OAuth2\Authorization\Exception\FailToLoadPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\NotExistedKeyException;
use Ridibooks\OAuth2\Authorization\Exception\RetryFailyException;
use Ridibooks\OAuth2\Constant\JWKConstant;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Ridibooks\OAuth2\Authorization\Api\JwkApi;
use DateTime;

class JwkHandler
{
    /** @var array */
    private $public_key_dtos = [];

    /** @var string */
    private $jwk_url;

    public function __construct(string $jwk_url)
    {
        $this->jwk_url = $jwk_url;
    }

    /**
     * @param string $client_id
     * @param string $kid
     * @return JWK
     * @throws InvalidJwtException
     * @throws FailToLoadPublicKeyException
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     */
    public function getPublicKeyByKid(
        string $client_id,
        string $kid
    ): JWK
    {
        $public_key_dto = $this->getMemorizedKeyDto($client_id, $kid);
        if (!$public_key_dto) {
            $public_key_dto = $this->resetKeyDtos($client_id, $kid);
        }


        $this->assertValidKey($public_key_dto);

        return $public_key_dto;
    }

    /**
     * @param string $client_id
     * @return bool
     * @throws \OutOfBoundsException
     */
    # TODO: 위에 왜 warning 주는지?
    protected function isExpiredKey(string $client_id): bool
    {
        return $this->public_key_dtos[$client_id][JWKConstant::JWK_EXPIRATION_AT_KEY] < new DateTime();
    }


    /**
     * @param string $client_id
     * @param string $kid
     * @return JWK|null
     * @throws InvalidJwtException
     */
    protected function getMemorizedKeyDto(
        string $client_id,
        string $kid
    ): ?JWK
    {
        if (!array_key_exists($client_id, $this->public_key_dtos) || $this->isExpiredKey($client_id)) {
            return null;
        }
        if (!array_key_exists($kid, $this->public_key_dtos[$client_id])) {
            throw new InvalidJwtException("No matched JWK in registered JWKSet");
        }

        return $this->public_key_dtos[$client_id][$kid];
    }

    /**
     * @param JWK $key
     * @return void
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     */
    protected function assertValidKey(
        JWK $key
    ): void
    {
        if (!$key) {
            throw new NotExistedKeyException();
        }
        if ($key->get('kty') != JWKConstant::RSA || $key->get('use') != JWKConstant::SIG) {
            throw new InvalidPublicKeyException();
        }
    }

    /**
     * @param JWK $client_id
     * @param JWK $kid
     * @return JWK
     * @throws FailToLoadPublicKeyException
     * @throws InvalidJwtException
     */
    protected function resetKeyDtos(
        string $client_id,
        string $kid
    ): JWK
    {
        try {
            $keys = $this->getValidPublicKeysByClientId($client_id);
        } catch (RetryFailyException $e) {
            throw new FailToLoadPublicKeyException();
        }

        $this->memorizeKeyDtos($client_id, $keys);

        return $this->getMemorizedKeyDto($client_id, $kid);
    }

    /**
     * @param string $client_id
     * @param JWKSet $jwkset
     * @return void
     * @throws \OutOfBoundsException
     */
    # TODO: 위에 왜 warning 주는지?
    protected function memorizeKeyDtos(
        string $client_id,
        JWKSet $jwkset
    ): void
    {
        if (array_key_exists($client_id, $this->public_key_dtos)) {
            $key_dtos = $this->public_key_dtos[$client_id];
        } else {
            $key_dtos = [];
        }

        foreach ($jwkset->all() as $kid => $jwk) {
            $key_dtos[$kid] = $jwk;
        }

        # TODO: 아래 변수를 그냥 string 에 박는 방법은 없는지 알아내서 간단하게 변경하자.
        $jwk_expiration_min = JWKConstant::JWK_EXPIRATION_SEC;
        $now_date = new DateTime();
        $key_dtos[JWKConstant::JWK_EXPIRATION_AT_KEY] = $now_date->modify("+${jwk_expiration_min} seconds");
        $this->public_key_dtos[$client_id] = $key_dtos;
    }

    /**
     * @param string $client_id
     * @return JWKSet
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    protected function getValidPublicKeysByClientId(
        string $client_id
    ): JWKSet
    {
        $public_key_array = JwkApi::requestPublicKey($this->jwk_url, $client_id);

        return JWKSet::createFromKeyData($public_key_array);
    }
}
