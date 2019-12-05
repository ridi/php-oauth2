<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Key;

use Ridibooks\OAuth2\Constant\JWKConstant;
use Symfony\Component\Validator\Constraints\DateTime;
use phpseclib\Crypt\RSA;

class JWKDto
{
    /**
     * @var string
     */
    public $alg;
    /**
     * @var string
     */
    public $kty;
    /**
     * @var string
     */
    public $use;
    /**
     * @var string
     */
    public $e;
    /**
     * @var string
     */
    public $n;
    /**
     * @var string
     */
    public $kid;
    /**
     * @var string
     */
    public $is_expired;
    /**
     * @var string
     */
    public $_json;
    /**
     * @var string
     */
    public $_expires;
    /**
     * @var string
     */
    public $public_key;


    /**
     * BaseTokenInfo constructor.
     *
     * @param string $subject
     * @param int $expire_timestamp
     * @param int $u_idx
     * @param string $client_id
     * @param array $scopes
     */
    public function __construct(
        string $json
    )
    {

        $this->_json = $json;
        $jwk_expireds_min = JWKConstant::JWK_EXPIRES_MIN;
        $date = new DateTime();
        $this->expires = $date->modify("+${jwk_expireds_min} minutes");

        $decoded_n = bytes_to_int(urlsafe_b64decode($this->n));
        $decoded_e = bytes_to_int(urlsafe_b64decode($this->e));
        $rsa_public_key = new RSA();

        $rsa_public_key->loadKey(array('e' => $decoded_e, 'n' => $decoded_n));
        $this->public_key = $rsa_public_key;
    }

}
