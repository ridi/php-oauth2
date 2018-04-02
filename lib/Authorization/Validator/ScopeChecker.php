<?php declare(strict_types=1);
namespace Ridibooks\OAuth2Resource\Authorization\Validator;

use Ridibooks\OAuth2Resource\Constant\ScopeConstant;

class ScopeChecker
{
    /**
     * @param array $require_scopes
     * @param array $user_scope
     * @return bool
     */
    public static function check(array $require_scopes, array $user_scope): bool
    {
        if (in_array(ScopeConstant::SCOPE_FULL_AUTHORITY, $user_scope)) {
            return true;
        }

        // Or 확인
        foreach ($require_scopes as $require_scope) {
            if (is_array($require_scope) && self::and($require_scope, $user_scope)) {
                return true;
            } elseif (in_array($require_scope, $user_scope)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array $require_scopes
     * @param array $user_scope
     * @return bool
     */
    private static function and (array $require_scopes, array $user_scope): bool
    {
        foreach ($require_scopes as $require_scope) {
            if (!in_array($require_scope, $user_scope)) {
                return false;
            }
        }

        return true;
    }
}
