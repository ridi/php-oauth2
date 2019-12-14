<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Authorization;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidTokenException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\Test\OAuth2\Common\TokenConstant;
use Mockery;

final class TokenValidatorTest extends TestCase
{
    protected function setUp()
    {
        $mock_data = <<<EOT
        {"keys":[
        {"kid": "RS999", "alg": "RS256", "kty": "RSA", "use": "sig", "n": "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==", "e": "AQAB"},
        {"kid": "kid1", "alg": "RS256", "kty": "RSA", "use": "sig", "n": "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==", "e": "AQAB"}
        ]}
EOT;
        Mockery::mock('alias:Ridibooks\OAuth2\Authorization\Key\KeyRequestor', [
            "requestPublicKey" => json_decode($mock_data, true),
        ]);
    }

    protected function tearDown()
    {
        Mockery::close();
    }

    private function validate($access_token)
    {
        return JwtTokenValidator::create()
            ->validateToken($access_token);
    }

    private function validateWithKid($access_token)
    {
        return JwtTokenValidator::create()
            ->validateToken($access_token);
    }

    public function testCanIntrospect()
    {
        $access_token = TokenConstant::TOKEN_VALID;
        $token = $this->validate($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testIntrospectExpiredToken()
    {
        $this->expectException(ExpiredTokenException::class);

        $access_token = TokenConstant::TOKEN_EXPIRED;
        $this->validate($access_token);
    }

    public function testCannotIntrospectWrongFormatToken()
    {
        $this->expectException(InvalidTokenException::class);

        $access_token = TokenConstant::TOKEN_INVALID_PAYLOAD;
        $this->validate($access_token);
    }

    public function testCannotIntrospectInvalidSignToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::TOKEN_INVALID_SIGNATURE;
        $this->validate($access_token);
    }

    public function testCannotIntrospectNullToken()
    {
        $this->expectException(TokenNotFoundException::class);

        $this->validate(null);
    }

    public function testCannotIntrospectEmptyToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::TOKEN_EMPTY;
        $this->validate($access_token);
    }

    public function testCanIntrospectWithKid()
    {
        $access_token = TokenConstant::KID_TOKEN_VALID;
        $token = $this->validateWithKid($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testCanIntrospectEmptyKid()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::KID_TOKEN_WITHOUT_KID;
        $token = $this->validateWithKid($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testCannotIntrospectWithInvalidKid()
    {
        $this->expectException(InvalidJwtException::class);
        $access_token = TokenConstant::KID_TOKEN_INVALID_KID;
        $this->validateWithKid($access_token);
    }
}
