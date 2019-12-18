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

const JWKS_CACHE_FILENAME = './jwksCache.php';
const JWKS_VAL_NAME = 'cached_jwks';

class JwkHandler
{
    /**
     * @param string $jwk_url
     * @param string $client_id
     * @param string $kid
     * @return JWK
     * @throws InvalidJwtException
     * @throws FailToLoadPublicKeyException
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     */
    public static function getPublicKeyByKid(
        string $jwk_url,
        string $client_id,
        string $kid
    ): JWK
    {
        $cached_jwks = self::getCachedJwks(JWKS_CACHE_FILENAME);
        $public_key_dto = self::getMemorizedKeyDto($cached_jwks, $client_id, $kid);
        if (!$public_key_dto) {
            $public_key_dto = self::resetKeyDtos($cached_jwks, $jwk_url, $client_id, $kid);
        }


        self::assertValidKey($public_key_dto);

        return $public_key_dto;
    }

    public static function setCacheJwks($fileName, $target)
    {
        // Serializing Targeted Data
        $target = str_replace('"', '\"', serialize($target));

        // Writing to Cache File
        $fp = fopen($fileName, 'w+');

        while (!flock($fp, LOCK_EX)) { # waiting if locked.
            var_dump("Waiting!!!");
            usleep(1000);
        }

        fwrite($fp, '<?php ');
        fwrite($fp, '$' . JWKS_VAL_NAME . ' = unserialize("' . $target . '");');
        fwrite($fp, ' ?>');
        fclose($fp); //  the lock is released also by fclose() (which is also called automatically when script finished).
    }

    public static function getCachedJwks($fileName, $ttl = 600): ?array
    {
        if(!file_exists($fileName) || filemtime($fileName) + $ttl < time())
        {
            return null;
        }

        include($fileName);
        $valName = JWKS_VAL_NAME;
        return $$valName;
    }

    /**
     * @param string $client_id
     * @return bool
     * @throws \OutOfBoundsException
     */
    # TODO: 위에 왜 warning 주는지?
    protected static function isExpiredKey(array $public_key_dtos, string $client_id): bool
    {

        return $public_key_dtos[$client_id][JWKConstant::JWK_EXPIRATION_AT_KEY] < new DateTime();
    }


    /**
     * @param array|null &$cached_jwks
     * @param string $client_id
     * @param string $kid
     * @return JWK|null
     * @throws InvalidJwtException
     */
    protected static function getMemorizedKeyDto(
        ?array &$cached_jwks,
        string $client_id,
        string $kid
    ): ?JWK
    {
        if ($cached_jwks == null) {
            return null;
        }
        if (!array_key_exists($client_id, $cached_jwks) || self::isExpiredKey($cached_jwks, $client_id)) {
            return null;
        }
        if (!array_key_exists($kid, $cached_jwks[$client_id])) {
            throw new InvalidJwtException("No matched JWK in registered JWKSet");
        }
        return $cached_jwks[$client_id][$kid];
    }

    /**
     * @param JWK $key
     * @return void
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     */
    protected static function assertValidKey(
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
     * @param array|null &$cached_jwks
     * @param string $jwk_url
     * @param string $client_id
     * @param string $kid
     * @return JWK
     * @throws FailToLoadPublicKeyException
     * @throws InvalidJwtException
     */
    protected static function resetKeyDtos(
        ?array &$cached_jwks,
        string $jwk_url,
        string $client_id,
        string $kid
    ): JWK
    {
        try {
            $keys = self::getValidPublicKeysByClientId($jwk_url, $client_id);
        } catch (RetryFailyException $e) {
            throw new FailToLoadPublicKeyException();
        }

        self::memorizeKeyDtos($cached_jwks, $client_id, $keys);

        return self::getMemorizedKeyDto($cached_jwks, $client_id, $kid);
    }

    /**
     * @param array|null &$cached_jwks
     * @param string $client_id
     * @param JWKSet $jwkset
     * @return void
     * @throws \OutOfBoundsException
     */
    # TODO: 위에 왜 warning 주는지?
    protected static function memorizeKeyDtos(
        ?array &$cached_jwks,
        string $client_id,
        JWKSet $jwkset
    ): void
    {
        if ($cached_jwks == null) {
            $cached_jwks = [];
        }

        if (array_key_exists($client_id, $cached_jwks)) {
            $key_dtos = $cached_jwks[$client_id];
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
        $cached_jwks[$client_id] = $key_dtos;

        self::setCacheJwks(JWKS_CACHE_FILENAME, $cached_jwks);
    }

    /**
     * @param string $client_id
     * @return JWKSet
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    protected static function getValidPublicKeysByClientId(
        string $jwk_url,
        string $client_id
    ): JWKSet
    {
        $public_key_array = JwkApi::requestPublicKey($jwk_url, $client_id);

        return JWKSet::createFromKeyData($public_key_array);
    }
}
