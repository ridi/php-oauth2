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
    private $jwk_cache_folder_path = './test_jwk_cache_folder';
    private $jwk_cache_file_path = './test_jwk_cache_folder/test_client_id.php';
    private $jwk_cache_file_path_2 = './test_jwk_cache_folder/test_client_id_2.php';
    private $client_id = 'test_client_id';
    private $client_id_2 = 'test_client_id_2';
    private $kid = 'RS999';

    protected function setUp()
    {
        MockJwkApi::setUp();
    }

    protected function tearDown()
    {
        MockJwkApi::tearDown();
        $this->removeCacheFile();
    }

    private function getJwkCacheValue() {
        $jwks = [];
        $mock_jwk_array = MockJwkApi::getMockJwkApiResponseBody()['keys'];
        foreach ($mock_jwk_array as $jwk) {
            $jwks[$jwk['kid']] = $jwk;
        }
        return $jwks;
    }

    private function setCacheFile() {
        CacheManager::setCache($this->jwk_cache_file_path, $this->getJwkCacheValue());
    }

    private function removeCacheFile() {
        if (file_exists($this->jwk_cache_file_path)) {
            unlink($this->jwk_cache_file_path);
        }

        if (file_exists($this->jwk_cache_file_path_2)) {
            unlink($this->jwk_cache_file_path_2);
        }
    }

    public function testCacheWorking()
    {
        self::setCacheFile();
        $cacheData = CacheManager::getCacheIfExist($this->jwk_cache_file_path);
        $this->assertEquals($this->getJwkCacheValue(), $cacheData);
        $this->assertFileExists($this->jwk_cache_file_path);
    }

    public function testReturnNullWhenFileNotExist()
    {
        $cacheData = CacheManager::getCacheIfExist($this->jwk_cache_file_path);

        $this->assertNull($cacheData);
    }

    public function testReturnNullAfterTTL()
    {
        self::setCacheFile();
        sleep(2);
        $cache_data = CacheManager::getCacheIfExist($this->jwk_cache_file_path, 1);

        $this->assertNull($cache_data);
    }

    public function testGetJwkWithoutCaching()
    {
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, $this->kid);
        $this->assertFileNotExists($this->jwk_cache_file_path);
        $this->assertInstanceOf(JWK::class, $JWK);
    }

    public function testGetJwkWithCaching()
    {
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, $this->kid, $this->jwk_cache_folder_path);
        $this->assertFileExists($this->jwk_cache_file_path);
        $this->assertInstanceOf(JWK::class, $JWK);
    }

    public function testGetJwkWithAlreadyCached()
    {
        $this->setCacheFile();
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, $this->kid, $this->jwk_cache_folder_path);
        $this->assertFileExists($this->jwk_cache_file_path);
        $this->assertInstanceOf(JWK::class, $JWK);
    }

    public function testMultiJwkCacheFileCreated()
    {
        $this->setCacheFile();
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, $this->kid, $this->jwk_cache_folder_path);
        $JWK2 = JwkHandler::getJwk($this->jwk_url, $this->client_id_2, $this->kid, $this->jwk_cache_folder_path);

        $this->assertFileExists($this->jwk_cache_file_path);
        $this->assertFileExists($this->jwk_cache_file_path_2);
        $this->assertInstanceOf(JWK::class, $JWK);
        $this->assertInstanceOf(JWK::class, $JWK2);
    }
}
