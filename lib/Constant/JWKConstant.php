<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Constant;

class JWKConstant
{
    const JWK_EXPIRATION_SEC = 300;
    const JWK_EXPIRATION_AT_KEY = 'expiration_at';

    const RSA = 'RSA';
    const EC = 'EC';
    const OCT= 'oct';

    const SIG= 'sig';
}
