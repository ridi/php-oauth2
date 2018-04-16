<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Authorization\Exception;

use Ridibooks\OAuth2\Constant\ScopeConstant;

class InsufficientScopeException extends AuthorizationException
{
    private $required_scopes;

    public function __construct(array $required_scopes)
    {
        parent::__construct(implode(ScopeConstant::DEFAULT_SCOPE_DELIMITER, $required_scopes) . ' are required.');
        $this->required_scopes = $required_scopes;
    }

    public function getRequiredScopes()
    {
        return $this->required_scopes;
    }
}
