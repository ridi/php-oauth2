<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Authorization\Validator;

use Ridibooks\OAuth2\Constant\ScopeConstant;

class ScopeChecker
{
    /**
     * @param array $required
     * @param array $granted
     * @return bool
     */
    public static function every(array $required, array $granted): bool
    {
        if (in_array(ScopeConstant::SCOPE_FULL_AUTHORITY, $granted)) {
            return true;
        }
        return empty(array_diff($required, $granted));
    }
}
