<?php declare(strict_types=1);
namespace Ridibooks\OAuth2Resource\Authorization\Validator;

use Lcobucci\JWT\Signer;

class JwtInfo
{
    const DEFAULT_EXPIRE_TERM = 60 * 5; // second

    /**
     * @var string
     */
    private $secret;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var integer
     */
    private $expire_term;

    /**
     * JwtInfo constructor.
     * @param string $secret
     * @param Signer $signer
     * @param int $expire_term
     */
    public function __construct(string $secret, Signer $signer, int $expire_term=JwtInfo::DEFAULT_EXPIRE_TERM)
    {
        $this->secret = $secret;
        $this->signer = $signer;
        $this->expire_term = $expire_term;
    }

    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        return $this->signer;
    }

    /**
     * @return int
     */
    public function getExpireTerm(): int
    {
        return $this->expire_term;
    }
}
