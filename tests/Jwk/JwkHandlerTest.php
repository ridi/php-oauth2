<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Authorization;

use Jose\Component\Core\JWK;
use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Cache\CacheManager;
use Ridibooks\OAuth2\Authorization\Jwk\JwkHandler;
use Ridibooks\Test\OAuth2\Api\MockJwkApi;


final class JwkHandlerTest extends TestCase
{
    private $jwk_url = 'https://account.dev.ridi.io/oauth2/keys/public';
    private $jwks;
    private $jwk_cache_filename = './testJwksCache.php';
    private $client_id = 'test_client_id';
    private $kid = 'RS999';

    protected function setUp()
    {
        MockJwkApi::setUp();
        $this->jwks = MockJwkApi::getMockJwkApiResponseBody();
    }

    protected function tearDown()
    {
        MockJwkApi::tearDown();
        $this->removeCacheFile();
    }

    private function setCacheFile() {
        CacheManager::setCache($this->jwk_cache_filename, $this->jwks);
    }

    private function removeCacheFile() {
        if (file_exists($this->jwk_cache_filename)) {
            unlink($this->jwk_cache_filename);
        }
    }

    public function testCacheWorking()
    {
        self::setCacheFile();
        $cacheData = CacheManager::getCache($this->jwk_cache_filename);
        $this->assertEquals($this->jwks, $cacheData);
        $this->assertFileExists($this->jwk_cache_filename);
    }

    public function testReturnNullWhenFileNotExist()
    {
        $cacheData = CacheManager::getCache($this->jwk_cache_filename);

        $this->assertNull($cacheData);
    }

    public function testReturnNullAfterTTL()
    {
        self::setCacheFile();
        sleep(2);
        $cache_data = CacheManager::getCache($this->jwk_cache_filename, 1);

        $this->assertNull($cache_data);
    }

    public function testGetPublicKeyByKidWithoutCaching()
    {
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, $this->kid);
        $this->assertFileNotExists($this->jwk_cache_filename);
        $this->assertInstanceOf(JWK::class, $JWK);
    }

    public function testGetPublicKeyByKidWithCaching()
    {
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, $this->kid, $this->jwk_cache_filename);
        $this->assertFileExists($this->jwk_cache_filename);
        $this->assertInstanceOf(JWK::class, $JWK);
    }

    public function testGetPublicKeyByKidWithAlreadyCached()
    {
        $this->setCacheFile();
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, $this->kid, $this->jwk_cache_filename);
        $this->assertFileExists($this->jwk_cache_filename);
        $this->assertInstanceOf(JWK::class, $JWK);
    }
}
