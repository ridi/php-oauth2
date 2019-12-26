<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Jwk;

use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\NotExistedKeyException;
use Ridibooks\OAuth2\Constant\JwkConstant;
use Jose\Component\Core\JWK;
use Ridibooks\OAuth2\Authorization\Api\JwkApi;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Cache\CacheException;

class JwkHandler
{
    /** @var CacheItemPoolInterface */
    private $cache_item_pool;

    /** @var string */
    private $jwk_url;

    /**
     * @param string $jwk_url
     * @param CacheItemPoolInterface|null $cache_item_pool
     * @return void
     */
    public function __construct(string $jwk_url, ?CacheItemPoolInterface $cache_item_pool = null)
    {
        $this->jwk_url = $jwk_url;
        $this->cache_item_pool = $cache_item_pool;
    }

    /**
     * @param string $client_id
     * @param string $kid
     * @return JWK
     * @throws InvalidJwtException
     * @throws NotExistedKeyException
     * @throws InvalidPublicKeyException
     * @throws AccountServerException
     * @throws ClientRequestException
     * @throws CacheException
     */
    public function getJwk(
        string $client_id,
        string $kid
    ): JWK
    {
        $jwk = !is_null($this->cache_item_pool) ? $this->getJwkFromCachePool($kid, $client_id) : null;
        if (is_null($jwk)) {
            $jwk = $this->getJwkFromApiAndMemorizeJwks($client_id, $kid);
        }

        $this->assertValidKey($jwk);

        return $jwk;
    }

    /**
     * @param string $kid
     * @param string $client_id
     * @return JWK|null
     * @throws InvalidJwtException
     * @throws CacheException
     */
    protected function getJwkFromCachePool(string $kid, string $client_id): ?JWK
    {
        $cached_jwks = $this->cache_item_pool->getItem($client_id);

        return $this->getJwkFromJwks($cached_jwks->get(), $kid);
    }

    /**
     * @param array|null $jwks
     * @param string $kid
     * @return JWK|null
     * @throws InvalidJwtException
     */
    protected function getJwkFromJwks(
        ?array $jwks,
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
    protected function assertValidKey(
        JWK $jwk
    ): void
    {
        if (!$jwk) {
            throw new NotExistedKeyException();
        }
        if ($jwk->get('use') != JwkConstant::SIG) {
            throw new InvalidPublicKeyException();
        }
    }

    /**
     * @param string $client_id
     * @param string $kid
     * @return JWK
     * @throws AccountServerException
     * @throws ClientRequestException
     * @throws InvalidJwtException
     * @throws CacheException
     */
    protected function getJwkFromApiAndMemorizeJwks(
        string $client_id,
        string $kid
    ): JWK
    {
        $jwk_array = $this->getJwkArrayFromJwkApi($client_id);
        $jwks = $this->getJwksFromJwkArray($client_id, $jwk_array);
        $this->setJwksToCachePool($client_id, $jwks);
        return $this->getJwkFromJwks($jwks, $kid);
    }

    /**
     * @param string $client_id
     * @return array
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    protected function getJwkArrayFromJwkApi(
        string $client_id
    ): array
    {
        return JwkApi::requestPublicKey($this->jwk_url, $client_id)[JwkConstant::KEYS];
    }

    /**
     * @param string $client_id
     * @param array $jwk_array
     * @return array
     * @throws CacheException
     */
    protected function getJwksFromJwkArray(
        string $client_id,
        array $jwk_array
    ): array
    {
        $jwks = [];
        if (!empty($this->cache_item_pool)) {
            $cached_jwks = $this->cache_item_pool->getItem($client_id)->get();
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
     * @return void
     * @throws CacheException
     */
    protected function setJwksToCachePool(
        string $client_id,
        array $jwks
    ): void
    {
        if (empty($this->cache_item_pool)) {
            return;
        }
        $cache_item = $this->cache_item_pool->getItem($client_id);
        $cache_item->set($jwks);
        $cache_item->expiresAfter(JwkConstant::JWK_EXPIRATION_SEC);
        $this->cache_item_pool->save($cache_item);
    }
}
