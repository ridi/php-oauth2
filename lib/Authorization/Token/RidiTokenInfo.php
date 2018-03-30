<?php

namespace Ridibooks\OAuth2Resource\Authorization\Token;


use Lcobucci\JWT\Token;
use Ridibooks\OAuth2Resource\Authorization\Token\BaseTokenInfo;
use Ridibooks\OAuth2Resource\Authorization\Validator\ScopeChecker;
use Ridibooks\OAuth2Resource\Constant\AuthorizationConstant;

class RidiTokenInfo extends BaseTokenInfo
{
    /**
     * @var int
     */
    private $u_idx;

    /**
     * @var string
     */
    private $client_id;

    /**
     * @var array
     */
    private $scopes;

    protected function __construct(string $subject, int $expire_timestamp, int $u_idx, string $client_id, array $scopes)
    {
        parent::__construct($subject, $expire_timestamp);
        $this->u_idx = $u_idx;
        $this->client_id = $client_id;
        $this->scopes = $scopes;
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
     * @return bool
     */
    public function isValid(): bool
    {
        return parent::isValid() && isset(
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

    /**
     * @param Token $token
     * @return RidiTokenInfo
     */
    public static function createFrom(Token $token)
    {
        $scope = $token->getClaim('scope');

        return new RidiTokenInfo(
            $token->getClaim('sub'),
            $token->getClaim('exp'),
            $token->getClaim('u_idx'),
            $token->getClaim('client_id'),
            explode(AuthorizationConstant::DEFAULT_SCOPE_DELIMITER, $scope)
        );
    }

}
