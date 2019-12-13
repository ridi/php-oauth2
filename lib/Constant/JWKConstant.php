<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Constant;

class JWKConstant
{
    const JWK_EXPIRES_MIN = 30;
    const JWK_EXPIRES_KEY = 'expires';

    const RSA = 'RSA';
    const EC = 'EC';
    const OCT= 'oct';

    const SIG= 'sig';
}
