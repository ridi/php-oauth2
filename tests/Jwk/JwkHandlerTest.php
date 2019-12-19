<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Authorization;

use Doctrine\Common\Cache\Cache;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Cache\CacheManager;
use Ridibooks\OAuth2\Authorization\Jwk\JwkHandler;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\Test\OAuth2\Common\TokenConstant;
use Ridibooks\Test\OAuth2\Api\MockJwkApi;


final class JwkHandlerTest extends TestCase
{
    private $jwk_url = 'https://account.dev.ridi.io/oauth2/keys/public';
    private $jwks = [];
    private $jwk_cache_filename = './jwksCache.php';
    private $client_id = 'test_client_id';

    protected function setUp()
    {
        MockJwkApi::setUp();
        $mock_data = <<<EOT
        {"keys":[
        {"kid": "RS999", "alg": "RS256", "kty": "RSA", "use": "sig", "n": "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==", "e": "AQAB"},
        {"kid": "kid1", "alg": "RS256", "kty": "RSA", "use": "sig", "n": "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==", "e": "AQAB"}
        ]}
EOT;
        $this->jwks = json_decode($mock_data, true);
    }

    protected function tearDown()
    {
        MockJwkApi::tearDown();

        if (file_exists($this->jwk_cache_filename)) {
            unlink($this->jwk_cache_filename);
        }
    }

    private function setCacheFile() {
        CacheManager::setCache($this->jwk_cache_filename, $this->jwks);
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

    public function testReturnNullShortTTL()
    {
        self::setCacheFile();
        sleep(1);
        $cache_data = CacheManager::getCache($this->jwk_cache_filename, 0.1);

        $this->assertNull($cache_data);
    }

    public function testGetPublicKeyByKidWithoutCaching()
    {
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, 'RS999');
        $this->assertFileNotExists($this->jwk_cache_filename);
        $this->assertInstanceOf(JWK::class, $JWK);
    }

    public function testGetPublicKeyByKidWithCaching()
    {
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, 'RS999', $this->jwk_cache_filename);
        $this->assertFileExists($this->jwk_cache_filename);
        $this->assertInstanceOf(JWK::class, $JWK);
    }

    public function testGetPublicKeyByKidWithAlreadyCached()
    {
        $this->setCacheFile();
        $JWK = JwkHandler::getJwk($this->jwk_url, $this->client_id, 'RS999', $this->jwk_cache_filename);
        $this->assertFileExists($this->jwk_cache_filename);
        $this->assertInstanceOf(JWK::class, $JWK);
    }
}
