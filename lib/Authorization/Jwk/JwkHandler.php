<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Jwk;

use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\NotExistedKeyException;
use Ridibooks\OAuth2\Authorization\Exception\RetryFailyException;
use Ridibooks\OAuth2\Constant\JwkConstant;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Ridibooks\OAuth2\Authorization\Api\JwkApi;
use Ridibooks\OAuth2\Authorization\Cache\CacheManager;


class JwkHandler
{
    /**
     * @param string $jwk_url
     * @param string $client_id
     * @param string $kid
     * @param string|null $jwk_cache_file_path
     * @return JWK
     * @throws InvalidJwtException
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    public static function getJwk(
        string $jwk_url,
        string $client_id,
        string $kid,
        ?string $jwk_cache_file_path = null
    ): JWK
    {
        $jwk = $jwk_cache_file_path ? self::getJwkFromCacheFile($kid, $client_id, $jwk_cache_file_path) : null;
        if (!$jwk) {
            $jwk = self::getJwkFromApiAndMemorizeJwks($jwk_url, $client_id, $kid, $jwk_cache_file_path);
        }

        self::assertValidKey($jwk);

        return $jwk;
    }

    /**
     * @param string $kid
     * @param string $client_id
     * @param string|null $jwk_cache_file_path
     * @return JWK|null
     * @throws InvalidJwtException
     */
    protected static function getJwkFromCacheFile($kid, $client_id, ?string $jwk_cache_file_path = null): ?JWK {
        if (!$jwk_cache_file_path) {
            return null;
        }
        $cached_jwks = CacheManager::getCache($jwk_cache_file_path, JwkConstant::JWK_EXPIRATION_SEC);
        return self::getJwkFromJwks($cached_jwks, $client_id, $kid);
    }

    /**
     * @param array|null &$jwks
     * @param string $client_id
     * @param string $kid
     * @return JWK|null
     * @throws InvalidJwtException
     */
    protected static function getJwkFromJwks(
        ?array &$jwks,
        string $client_id,
        string $kid
    ): ?JWK
    {
        if ($jwks == null) {
            return null;
        }
        if (!array_key_exists($client_id, $jwks)) {
            return null;
        }
        if (!array_key_exists($kid, $jwks[$client_id])) {
            throw new InvalidJwtException("No matched JWK in registered JWKSet");
        }

        return $jwks[$client_id][$kid];
    }

    /**
     * @param JWK $jwk
     * @return void
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     */
    protected static function assertValidKey(
        JWK $jwk
    ): void
    {
        if (!$jwk) {
            throw new NotExistedKeyException();
        }
        if ($jwk->get('kty') != JwkConstant::RSA || $jwk->get('use') != JwkConstant::SIG) {
            throw new InvalidPublicKeyException();
        }
    }

    /**
     * @param string $jwk_url
     * @param string $client_id
     * @param string $kid
     * @param string|null $jwk_cache_file_path
     * @return JWK
     * @throws AccountServerException
     * @throws ClientRequestException
     * @throws InvalidJwtException
     */
    protected static function getJwkFromApiAndMemorizeJwks(
        string $jwk_url,
        string $client_id,
        string $kid,
        ?string $jwk_cache_file_path = null
    ): JWK
    {
        $jwkSet = self::getJwkSetFromJwkApi($jwk_url, $client_id);
        $jwks = self::getJwksFromJwkSet($client_id, $jwkSet, $jwk_cache_file_path);
        self::setJwksToCacheFile($jwks, $jwk_cache_file_path);

        return self::getJwkFromJwks($jwks, $client_id, $kid);
    }

    /**
     * @param string $jwk_url
     * @param string $client_id
     * @return JWKSet
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    protected static function getJwkSetFromJwkApi(
        string $jwk_url,
        string $client_id
    ): JWKSet
    {
        $public_key_array = JwkApi::requestPublicKey($jwk_url, $client_id);

        return JWKSet::createFromKeyData($public_key_array);
    }

    /**
     * @param string $client_id
     * @param JWKSet $jwkSet
     * @param string|null $jwk_cache_file_path
     * @return array
     */
    protected static function getJwksFromJwkSet(
        string $client_id,
        JWKSet $jwkSet,
        ?string $jwk_cache_file_path = null
    ): array
    {
        $cached_jwks = CacheManager::getCache($jwk_cache_file_path, JwkConstant::JWK_EXPIRATION_SEC);
        $jwks = $cached_jwks ? $cached_jwks : [];
        $client_jwks = array_key_exists($client_id, $jwks) ? jwks[$client_id] : [];
        foreach ($jwkSet->all() as $kid => $jwk) {
            $client_jwks[$kid] = $jwk;
        }
        $jwks[$client_id] = $client_jwks;

        return $jwks;
    }

    /**
     * @param array $jwks
     * @param string|null $jwk_cache_file_path
     * @return void
     */
    protected static function setJwksToCacheFile(
        array $jwks,
        ?string $jwk_cache_file_path
    ): void
    {
        if ($jwk_cache_file_path) {
            CacheManager::setCache($jwk_cache_file_path, $jwks);
        }
    }
}
