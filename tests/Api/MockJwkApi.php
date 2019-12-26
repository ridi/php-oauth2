<?php declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Api;

use Mockery;

class MockJwkApi
{
    static public function getMockJwkApiResponseBody(): array
    {
        return array(
            "keys" => array(
                array(
                    "kid" => "RS999",
                    "alg" => "RS256",
                    "kty" => "RSA",
                    "use" => "sig",
                    "n" => "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==",
                    "e" => "AQAB",
                ),
                array(
                    "kty" => "EC",
                    "use" => "sig",
                    "crv" => "P-256",
                    "kid" => "kid1",
                    "x" => "fCYTdzi-ZXsRFAYUv0JH5Zspa3ELj_Oc898-uhQvks4",
                    "y" => "aeGkxQvGFysWEwac0FC5y9oUul3GqvExo8rFkXcc-jg",
                    "alg" => "ES256"
                )
            )
        );
    }

    static public function setUp()
    {
        Mockery::mock('alias:Ridibooks\OAuth2\Authorization\Api\JwkApi', [
            "requestPublicKey" => self::getMockJwkApiResponseBody(),
        ]);
    }

    static public function tearDown()
    {
        Mockery::close();
    }
}
