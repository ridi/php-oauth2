<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Constant;

class AccessTokenConstant
{
    const ACCESS_TOKEN_INFO_KEY = 'access_token_info';
    const ACCESS_TOKEN_COOKIE_KEY = 'ridi-at';

    const DEFAULT_EXPIRE_MARGIN = 60 * 5;   // seconds
}
