<?php declare(strict_types=1);
namespace Ridibooks\OAuth2Resource\Constant;

class GrantErrorCodeConstant
{
    const INVALID_REQUEST = 'invalid_request';
    const INVALID_CLIENT = 'invalid_client';
    const INVALID_GRANT = 'invalid_grant';
    const UNAUTHORIZED_CLIENT = 'unauthorized_client';
    const UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';
    const INVALID_SCOPE = 'invalid_scope';
}
