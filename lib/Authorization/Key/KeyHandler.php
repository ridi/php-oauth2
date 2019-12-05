<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Token;

use GuzzleHttp\Psr7\Response;
use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;
use Ridibooks\OAuth2\Authorization\Exception\FailToLoadPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidPublicKeyException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidTokenException;
use Ridibooks\OAuth2\Authorization\Exception\NotExistedKeyException;
use Ridibooks\OAuth2\Authorization\Exception\RetryFailyException;
use Ridibooks\OAuth2\Authorization\Key\JWKDto;
use Ridibooks\OAuth2\Authorization\Validator\ScopeChecker;
use Ridibooks\OAuth2\Constant\JWKConstant;
use GuzzleHttp\Client;


class KeyHandler
{
    protected $public_key_dtos = [];


    /**
     * @var array
     */


    protected function _get_memorized_key_dto(
        string $client_id,
        string $kid
    ): JWKDto
    {
        return $this->public_key_dtos[client_id][kid];
    }

    /**
     * BaseTokenInfo constructor.
     *
     * @param string $client_id
     * @param string $kid
     */
    public function get_public_key_by_kid(
        string $client_id,
        string $kid
    )
    {
        $public_key_dto = this._get_memorized_key_dto($client_id, $kid);

        if (!($public_key_dto || $public_key_dto.is_expired)) {
            $$public_key_dto = cls._reset_key_dtos(client_id, kid);
        }

        cls._assert_valid_key($public_key_dto);

        return $public_key_dto.public_key;
    }

    static function _assert_valid_key(
        JWKDto $key
    )
    {
        if (!$key){
            throw new NotExistedKeyException();
        }

        if ($key->kty != JWKConstant::RSA || $key->use != JWKConstant::SIG) {
            throw new InvalidPublicKeyException();
        }
    }

    protected function _reset_key_dtos(
        string $client_id,
        string $kid
    ): JWKDto
    {
        try {
            $keys = $this->_get_valid_public_keys_by_client_id($client_id);
        } catch(RetryFailyException $e) {
            throw new FailToLoadPublicKeyException();
        }

        $this->_memorize_key_dtos($client_id, $keys);

        return $this->_get_memorized_key_dto($client_id, $kid);
    }

    /**
     * BaseTokenInfo constructor.
     *
     * @param string $client_id
     * @param JWKDto[] $keys
     */
    protected function _memorize_key_dtos(
        string $client_id,
        array $keys
    )
    {
        $key_dtos = $this->public_key_dtos[client_id];
        foreach ($keys as $key) {
            $key_dtos[$key->kid] = $key;
        }

        $this->public_key_dtos[$client_id] = $key_dtos;
    }

    static function _process_response(
        Response $response
    )
    {
        if ($response.status_code >= 500) {
            throw new AccountServerException();
        } else if ($response.status_code >= 400) {
            throw new ClientRequestException();
        }

        return $response.json();
    }


    protected function _get_valid_public_keys_by_client_id(
        string $client_id
    ) {
        # TODO: 리팩토링하자.
        $client = new Client();
        $response = $client->request('GET', RidiOAuth2Config.get_key_url(), [
            'query' => ['client_id' => $client_id]
        ]);

        $key_array = KeyHandler::_process_response($response).get('keys');
        array_map( function($key) {
            return new JWKDto($key); }, $key_array
        );
    }
}
