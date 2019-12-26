<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Token;

use Ridibooks\OAuth2\Authorization\Exception\InvalidTokenException;
use Ridibooks\OAuth2\Authorization\Validator\ScopeChecker;
use Ridibooks\OAuth2\Constant\ScopeConstant;

class JwtToken
{
    /**
     * @var string
     */
    protected $subject;
    /**
     * @var int
     */
    protected $expire_timestamp;
    /**
     * @var \DateTime
     */
    protected $expire_date;
    /**
     * @var array
     */
    protected $scopes;
    /**
     * @var int
     */
    protected $u_idx;
    /**
     * @var string
     */
    protected $client_id;

    /**
     * BaseTokenInfo constructor.
     *
     * @param string $subject
     * @param int $expire_timestamp
     * @param int $u_idx
     * @param string $client_id
     * @param array $scopes
     */
    protected function __construct(
        string $subject,
        int $expire_timestamp,
        int $u_idx,
        string $client_id,
        array $scopes
    )
    {
        $this->subject = $subject;
        $this->expire_timestamp = $expire_timestamp;
        $this->expire_date = (new \DateTime())->setTimestamp($expire_timestamp);
        $this->u_idx = $u_idx;
        $this->client_id = $client_id;
        $this->scopes = $scopes;
    }

    /**
     * @param array $token
     * @return JwtToken
     * @throws InvalidTokenException
     */
    public static function createFrom(array $token): JwtToken
    {
        if (!isset($token['sub'], $token['exp'], $token['u_idx'], $token['client_id'], $token['scope'])) {
            throw new InvalidTokenException();
        }
        return new self(
            $token['sub'],
            $token['exp'],
            $token['u_idx'],
            $token['client_id'],
            explode(ScopeConstant::DEFAULT_SCOPE_DELIMITER, $token['scope'])
        );
    }

    /**
     * @return string
     */
    public function getSubject(): string
    {
        return $this->subject;
    }

    /**
     * @return int
     */
    public function getExpireTimestamp(): int
    {
        return $this->expire_timestamp;
    }

    /**
     * @return \DateTime
     */
    public function getExpireDate(): \DateTime
    {
        return $this->expire_date;
    }

    /**
     * @return int
     */
    public function getUIdx(): int
    {
        return $this->u_idx;
    }

    /**
     * @return string
     */
    public function getClientId(): string
    {
        return $this->client_id;
    }

    /**
     * @return array
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @param array $scopes
     * @return bool
     */
    public function hasScopes(array $scopes): bool
    {
        return ScopeChecker::every($scopes, $this->getScopes());
    }
}
