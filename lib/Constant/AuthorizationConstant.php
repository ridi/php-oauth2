<?php
namespace Ridibooks\OAuth2Resource\Constant;

class AuthorizationConstant
{
    const ACCESS_TOKEN_INFO_KEY = 'access_token_info';
    const ACCESS_TOKEN_COOKIE_KEY = 'ridi-at';

    const DEFAULT_EXPIRE_MARGIN = 60 * 5;   // seconds

    const SCOPE_FULL_AUTHORITY = ScopeConstant::ALL;
    const DEFAULT_SCOPE_DELIMITER = ' ';
}
