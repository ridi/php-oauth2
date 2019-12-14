<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Key;

use Jose\Component\Core\JWK;
use Ridibooks\OAuth2\Authorization\Exception\FailToLoadPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\NotExistedKeyException;
use Ridibooks\OAuth2\Authorization\Exception\RetryFailyException;
use Ridibooks\OAuth2\Constant\JWKConstant;
use Jose\Component\Core\JWKSet;
use DateTime;

class KeyHandler
{
    /** @var int */
    private $expire_term = JWKConstant::JWK_EXPIRES_MIN;
    private $public_key_dtos = [];

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

    public function setExpireTerm(int $expire_term) {
        $this->expire_term = $expire_term;
    }
    protected function isExpiredKey($client_id): bool {
        return $this->public_key_dtos[$client_id][JWKConstant::JWK_EXPIRES_KEY] < new DateTime();
    }

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

    protected function assertValidKey(
        JWK $key
    )
    {
        if (!$key) {
            throw new NotExistedKeyException();
        }
        if ($key->get('kty') != JWKConstant::RSA || $key->get('use') != JWKConstant::SIG) {
            throw new InvalidPublicKeyException();
        }
    }

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

    protected function memorizeKeyDtos(
        string $client_id,
        $jwkset
    )
    {
        if (array_key_exists($client_id, $this->public_key_dtos)) {
            $key_dtos = $this->public_key_dtos[$client_id];
        } else {
            $key_dtos = [];
        }

        foreach ($jwkset->all() as $kid => $jwk) {
            $key_dtos[$kid] = $jwk;
        }

        $this->public_key_dtos[$client_id] = $key_dtos;

        $jwk_expireds_min = $this->expire_term;
        $date = new DateTime();
        $this->public_key_dtos[$client_id][JWKConstant::JWK_EXPIRES_KEY] = $date->modify("+${jwk_expireds_min} minutes");
    }


    protected function getValidPublicKeysByClientId(
        string $client_id
    ): JWKSet
    {
        $data = KeyRequestor::requestPublicKey($client_id);

        return JWKSet::createFromKeyData($data);
    }
}
