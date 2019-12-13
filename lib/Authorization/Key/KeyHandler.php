<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Key;

use GuzzleHttp\Psr7\Response;
use Jose\Component\Core\JWK;
use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;
use Ridibooks\OAuth2\Authorization\Exception\FailToLoadPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\NotExistedKeyException;
use Ridibooks\OAuth2\Authorization\Exception\RetryFailyException;
use Ridibooks\OAuth2\Constant\JWKConstant;
use GuzzleHttp\Client;
use Jose\Component\Core\JWKSet;
use DateTime;

class KeyHandler
{
    protected static $public_key_dtos = [];

    protected static function _is_expired_key($client_id): bool {
        return self::$public_key_dtos[$client_id][JWKConstant::JWK_EXPIRES_KEY] < new DateTime();
    }

    protected static function _get_memorized_key_dto(
        string $client_id,
        string $kid
    ): ?JWK
    {
        if (!array_key_exists($client_id, self::$public_key_dtos) || self::_is_expired_key($client_id)) {
            return null;
        }

        return self::$public_key_dtos[$client_id][$kid];
    }

    public static function get_public_key_by_kid(
        string $client_id,
        string $kid
    ): JWK
    {
        $public_key_dto = self::_get_memorized_key_dto($client_id, $kid);
        if (!$public_key_dto) {
            $public_key_dto = self::_reset_key_dtos($client_id, $kid);
        }


        self::_assert_valid_key($public_key_dto);
//        return "-----BEGIN PUBLIC KEY-----
//MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1rL5PCEv2PaAASaGldzf
//nlo0MiMCglC+eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP/QDk3
//NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg/
//FuplBFT82e14UVmZx4kP+HwDjaSpvYHoTr3b5j20Ebx7aIy/SVrWeY0wxeAdFf+E
//OuEBQ+QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsB
//LCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAn
//IQIDAQAB
//-----END PUBLIC KEY-----";
        return $public_key_dto;
    }

    protected static function _assert_valid_key(
        JWK $key
    )
    {
        if (!$key) {
            throw new NotExistedKeyException();
        }
        if ($key->get('kty') != JWKConstant::RSA || $key->get('use') != JWKConstant::SIG) {
            throw new InvalidPublicKeyException();
        }
    }

    protected static function _reset_key_dtos(
        string $client_id,
        string $kid
    ): JWK
    {
        try {
            $keys = self::_get_valid_public_keys_by_client_id($client_id);
        } catch (RetryFailyException $e) {
            throw new FailToLoadPublicKeyException();
        }

        self::_memorize_key_dtos($client_id, $keys);

        return self::_get_memorized_key_dto($client_id, $kid);
    }

    /**
     *
     * BaseTokenInfo constructor.
     *
     * @param string $client_id
     * @param JWKSet $jwkset
     */
    protected static function _memorize_key_dtos(
        string $client_id,
        $jwkset
    )
    {
        if (array_key_exists($client_id, self::$public_key_dtos)) {
            $key_dtos = self::$public_key_dtos[$client_id];
        } else {
            $key_dtos = [];
        }

        foreach ($jwkset->all() as $kid => $jwk) {
            $key_dtos[$kid] = $jwk;
        }

        self::$public_key_dtos[$client_id] = $key_dtos;

        $jwk_expireds_min = JWKConstant::JWK_EXPIRES_MIN;
        $date = new DateTime();
        self::$public_key_dtos[$client_id][JWKConstant::JWK_EXPIRES_KEY] = $date->modify("+${jwk_expireds_min} minutes");


    }

    static function _process_response(
        Response $response
    )
    {

        if ($response->getStatusCode() >= 500) {
            throw new AccountServerException();
        } else if ($response->getStatusCode() >= 400) {
            throw new ClientRequestException();
        }

        $json_decode = json_decode($response->getBody()->getContents(), true);
        return $json_decode;
    }


    protected static function _get_valid_public_keys_by_client_id(
        string $client_id
    )
    {
        # TODO: 리팩토링하자.
//        $oauth2_service_provider->getConfigs()['token_cookie_domain']
        $client = new Client();
        # TODO: 나중에 $client_id 넣자.
        $response = $client->request('GET',
            'https://account.dev.ridi.io/oauth2/keys/public', [
                'query' => ['client_id' => 'Nkt2Xdc0zMuWmye6MSkYgqCh9q6JjeMCsUiH1kgL']
            ]);

        $key_array = KeyHandler::_process_response($response);

        # TODO: $key_araay 나중에 위에걸로 바꾸자.
        $mock_data = <<<EOT
        {"keys":[{"kid": "RS999", "alg": "RS256", "kty": "RSA", "use": "sig", "n": "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==", "e": "AQAB"}]
        }
EOT;

        $key_array = json_decode($mock_data, true);


        return JWKSet::createFromKeyData($key_array);
    }
}
