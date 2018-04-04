<?php declare(strict_types=1);
namespace Ridibooks\OAuth2Resource\Authorization\Token;

use Lcobucci\JWT\Token;
use Ridibooks\OAuth2Resource\Authorization\Validator\ScopeChecker;
use Ridibooks\OAuth2Resource\Constant\AccessTokenConstant;
use Ridibooks\OAuth2Resource\Constant\ScopeConstant;

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
     * @param Token $token
     * @return JwtToken
     */
    public static function createFrom(Token $token): JwtToken
    {
        $scope = $token->getClaim('scope');

        return new self(
            $token->getClaim('sub'),
            $token->getClaim('exp'),
            $token->getClaim('u_idx'),
            $token->getClaim('client_id'),
            explode(ScopeConstant::DEFAULT_SCOPE_DELIMITER, $scope)
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
     * @param int $margin
     * @return bool
     */
    public function isExpired(int $margin = AccessTokenConstant::DEFAULT_EXPIRE_MARGIN): bool
    {
        $expired = $this->getExpireTimestamp();
        return isset($expired) ? $expired + $margin < time() : true;
    }

    /**
     * @return bool
     */
    public function isValid(): bool
    {
        return isset(
            $this->subject,
            $this->expire_timestamp,
            $this->u_idx,
            $this->client_id,
            $this->scopes
        );
    }

    /**
     * @param array $scopes
     * @return bool
     */
    public function hasScopes(array $scopes): bool
    {
        return ScopeChecker::check($scopes, $this->getScopes());
    }
}
