<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Authorization\Validator;

use Ridibooks\OAuth2\Constant\ScopeConstant;

class ScopeChecker
{
    /**
     * @param array $required_scopes
     *    e.g. ['a', 'b', ['c', 'd']] => 'a' or 'b' or ('c' and 'd')
     * @param array $user_scopes
     * @return bool
     */
    public function check(array $required_scopes, array $user_scopes): bool
    {
        if (in_array(ScopeConstant::SCOPE_FULL_AUTHORITY, $user_scopes)) {
            return true;
        }

        return self::some($required_scopes, $user_scopes);
    }

    /**
     * @param array $required_scopes
     * @param array $user_scopes
     * @return bool
     */
    private function some(array $required_scopes, array $user_scopes): bool
    {
        foreach ($required_scopes as $required_scope) {
            if (is_array($required_scope) && self::every($required_scope, $user_scopes)) {
                return true;
            } elseif (in_array($required_scope, $user_scopes)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param array $required_scopes
     * @param array $user_scopes
     * @return bool
     */
    private function every(array $required_scopes, array $user_scopes): bool
    {
        foreach ($required_scopes as $required_scope) {
            if (!in_array($required_scope, $user_scopes)) {
                return false;
            }
        }

        return true;
    }
}
