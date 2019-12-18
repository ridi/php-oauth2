<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Authorization;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
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
        JwkHandler::setCacheJwks($this->jwk_cache_filename, $this->jwks);
    }

    public function testCacheWorking()
    {
        self::setCacheFile();
        $cacheData = JwkHandler::getCachedJwks($this->jwk_cache_filename);
        $this->assertEquals($this->jwks, $cacheData);
        $this->assertFileExists($this->jwk_cache_filename);
    }

    public function testReturnNullWhenFileNotExist()
    {
        $cacheData = JwkHandler::getCachedJwks($this->jwk_cache_filename);

        $this->assertNull($cacheData);
    }

    public function testReturnNullShortTTL()
    {
        self::setCacheFile();
        sleep(1);
        $cache_data = JwkHandler::getCachedJwks($this->jwk_cache_filename, 0.1);

        $this->assertNull($cache_data);
    }

    public function testCacheWorkingWithJwk()
    {
        JwkHandler::getPublicKeyByKid($this->jwk_url, $this->client_id, 'RS999');
        $cached_jwks = JwkHandler::getCachedJwks($this->jwk_cache_filename);
        $this->assertArrayHasKey($this->client_id, $cached_jwks);
        $this->assertFileExists($this->jwk_cache_filename);
    }
}
