<?php
namespace Ridibooks\OAuth2Resource\Resource;

use Ridibooks\OAuth2Resource\Resource\Constant\Scope;

class ScopeChecker {
    /**
     * @param array $require_scopes
     * @param array $user_scope
     * @return bool
     */
    public static function check(array $require_scopes, array $user_scope): bool
    {
        if (in_array(Scope::ALL, $user_scope)) {
            return true;
        }

        // Or 확인
        foreach ($require_scopes as $require_scope) {
            if (is_array($require_scope) && ScopeChecker::and($require_scope, $user_scope)) {
                return true;
            } else if (in_array($require_scope, $user_scope)) {
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
    private static function and(array $require_scopes, array $user_scope): bool
    {
        foreach ($require_scopes as $require_scope) {
            if (!in_array($require_scope, $user_scope)) {
                return false;
            }
        }

        return true;
    }
}