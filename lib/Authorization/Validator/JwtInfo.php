<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Authorization\Validator;

class JwtInfo
{
    const DEFAULT_EXPIRE_TERM = 60 * 5; // second

    /**
     * @var string
     */
    private $secret;

    /**
     * @var string
     */
    private $algorithm;

    /**
     * @var int
     */
    private $expire_term;

    /**
     * JwtInfo constructor.
     *
     * @param string $secret
     * @param string $algorithm
     * @param int $expire_term
     */
    public function __construct(string $secret, string $algorithm, int $expire_term = JwtInfo::DEFAULT_EXPIRE_TERM)
    {
        $this->secret = $secret;
        $this->algorithm = $algorithm;
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
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @return int
     */
    public function getExpireTerm(): int
    {
        return $this->expire_term;
    }
}
