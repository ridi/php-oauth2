<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Jwk;

use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\CacheFileIOException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\NotExistedKeyException;
use Ridibooks\OAuth2\Authorization\Exception\RetryFailyException;
use Ridibooks\OAuth2\Constant\JwkConstant;
use Jose\Component\Core\JWK;
use Ridibooks\OAuth2\Authorization\Api\JwkApi;
use Ridibooks\OAuth2\Authorization\Cache\CacheManager;


class JwkHandler
{
    /**
     * @param string $jwk_url
     * @param string $client_id
     * @param string $kid
     * @param string|null $jwk_cache_folder_path
     * @return JWK
     * @throws InvalidJwtException
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     * @throws AccountServerException
     * @throws ClientRequestException
     * @throws CacheFileIOException
     */
    public static function getJwk(
        string $jwk_url,
        string $client_id,
        string $kid,
        ?string $jwk_cache_folder_path = null
    ): JWK
    {
        $jwk = $jwk_cache_folder_path ? self::getJwkFromCacheFile($kid, $client_id, $jwk_cache_folder_path) : null;
        if (is_null($jwk)) {
            $jwk = self::getJwkFromApiAndMemorizeJwks($jwk_url, $client_id, $kid, $jwk_cache_folder_path);
        }

        self::assertValidKey($jwk);

        return $jwk;
    }

    /**
     * @param string $kid
     * @param string $client_id
     * @param string|null $jwk_cache_folder_path
     * @return JWK|null
     * @throws InvalidJwtException
     */
    protected static function getJwkFromCacheFile(string $kid, string $client_id, ?string $jwk_cache_folder_path = null): ?JWK
    {
        if (empty($jwk_cache_folder_path)) {
            return null;
        }
        $cached_jwks = CacheManager::getCacheIfExist(
            self::getJwksCacheFilePath($client_id, $jwk_cache_folder_path),
            JwkConstant::JWK_EXPIRATION_SEC
        );
        return self::getJwkFromJwks($cached_jwks, $kid);
    }

    /**
     * @param array|null &$jwks
     * @param string $kid
     * @return JWK|null
     * @throws InvalidJwtException
     */
    protected static function getJwkFromJwks(
        ?array &$jwks,
        string $kid
    ): ?JWK
    {
        if (is_null($jwks)) {
            return null;
        }
        if (!array_key_exists($kid, $jwks)) {
            throw new InvalidJwtException("No matched JWK in registered JWKSet");
        }
        return JWK::createFromJson(json_encode($jwks[$kid]));
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
     * @param string|null $jwk_cache_folder_path
     * @return JWK
     * @throws AccountServerException
     * @throws ClientRequestException
     * @throws InvalidJwtException
     * @throws CacheFileIOException
     */
    protected static function getJwkFromApiAndMemorizeJwks(
        string $jwk_url,
        string $client_id,
        string $kid,
        ?string $jwk_cache_folder_path = null
    ): JWK
    {
        $jwk_array = self::getJwkArrayFromJwkApi($jwk_url, $client_id);
        $jwks = self::getJwksFromJwkArray($client_id, $jwk_array, $jwk_cache_folder_path);

        self::setJwksToCacheFile($client_id, $jwks, $jwk_cache_folder_path);
        return self::getJwkFromJwks($jwks, $kid);
    }

    /**
     * @param string $jwk_url
     * @param string $client_id
     * @return array
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    protected static function getJwkArrayFromJwkApi(
        string $jwk_url,
        string $client_id
    ): array
    {
        return JwkApi::requestPublicKey($jwk_url, $client_id)[JwkConstant::KEYS];
    }

    /**
     * @param string $client_id
     * @param array $jwk_array
     * @param string|null $jwk_cache_folder_path
     * @return array
     */
    protected static function getJwksFromJwkArray(
        string $client_id,
        array $jwk_array,
        ?string $jwk_cache_folder_path = null
    ): array
    {
        $jwks = [];
        if (!empty($jwk_cache_folder_path)) {
            $cached_jwks = CacheManager::getCacheIfExist(
                self::getJwksCacheFilePath($client_id, $jwk_cache_folder_path),
                JwkConstant::JWK_EXPIRATION_SEC
            );
            $jwks = !is_null($cached_jwks) ? $cached_jwks : [];
        }

        foreach ($jwk_array as $jwk) {
            $jwks[$jwk[JwkConstant::KID]] = $jwk;
        }

        return $jwks;
    }

    /**
     * @param string $client_id
     * @param array $jwks
     * @param string|null $jwk_cache_folder_path
     * @return void
     * @throws CacheFileIOException
     */
    protected static function setJwksToCacheFile(
        string $client_id,
        array $jwks,
        ?string $jwk_cache_folder_path = null
    ): void
    {
        if (!empty($jwk_cache_folder_path)) {
            CacheManager::setCache(
                self::getJwksCacheFilePath($client_id, $jwk_cache_folder_path),
                $jwks
            );
        }
    }

    /**
     * @param string $client_id
     * @param string $jwk_cache_folder_path
     * @return string
     */
    protected static function getJwksCacheFilePath(
        string $client_id,
        string $jwk_cache_folder_path
    ): string
    {
        return "{$jwk_cache_folder_path}/{$client_id}.php";
    }
}
