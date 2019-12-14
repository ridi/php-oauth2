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
    protected static $public_key_dtos = [];

    protected static function isExpiredKey($client_id): bool {
        return self::$public_key_dtos[$client_id][JWKConstant::JWK_EXPIRES_KEY] < new DateTime();
    }

    protected static function getMemorizedKeyDto(
        string $client_id,
        string $kid
    ): ?JWK
    {
        if (!array_key_exists($client_id, self::$public_key_dtos) || self::isExpiredKey($client_id)) {
            return null;
        }
        if (!array_key_exists($kid, self::$public_key_dtos[$client_id])) {
            throw new InvalidJwtException("No matched JWK in registered JWKSet");
        }

        return self::$public_key_dtos[$client_id][$kid];
    }

    public static function getPublicKeyByKid(
        string $client_id,
        string $kid
    ): JWK
    {
        $public_key_dto = self::getMemorizedKeyDto($client_id, $kid);
        if (!$public_key_dto) {
            $public_key_dto = self::resetKeyDtos($client_id, $kid);
        }


        self::assertValidKey($public_key_dto);

        return $public_key_dto;
    }

    protected static function assertValidKey(
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

    protected static function resetKeyDtos(
        string $client_id,
        string $kid
    ): JWK
    {
        try {
            $keys = self::getValidPublicKeysByClientId($client_id);
        } catch (RetryFailyException $e) {
            throw new FailToLoadPublicKeyException();
        }

        self::memorizeKeyDtos($client_id, $keys);

        return self::getMemorizedKeyDto($client_id, $kid);
    }

    protected static function memorizeKeyDtos(
        string $client_id,
        $jwkset
    )
    {
        if (array_key_exists($client_id, self::$public_key_dtos)) {
            $key_dtos = self::$public_key_dtos[$client_id];
        } else {
            $key_dtos = [];
        }

        foreach ($jwkset->all() as $kid => $jwk) {
            $key_dtos[$kid] = $jwk;
        }

        self::$public_key_dtos[$client_id] = $key_dtos;

        $jwk_expireds_min = JWKConstant::JWK_EXPIRES_MIN;
        $date = new DateTime();
        self::$public_key_dtos[$client_id][JWKConstant::JWK_EXPIRES_KEY] = $date->modify("+${jwk_expireds_min} minutes");


    }


    protected static function getValidPublicKeysByClientId(
        string $client_id
    ): JWKSet
    {
        $data = KeyRequestor::requestPublicKey($client_id);

        return JWKSet::createFromKeyData($data);
    }
}
