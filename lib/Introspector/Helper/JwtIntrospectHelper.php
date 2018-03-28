<?php
namespace Ridibooks\OAuth2Resource\Introspector\Helper;

use InvalidArgumentException;
use Ridibooks\OAuth2Resource\Introspector\DataTransferObject\AccessTokenInfo;
use Ridibooks\OAuth2Resource\Introspector\DataTransferObject\JwtInfo;
use Ridibooks\OAuth2Resource\Introspector\Exception\ExpireTokenException;
use Ridibooks\OAuth2Resource\Introspector\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2Resource\Introspector\JwtIntrospector;

class JwtIntrospectHelper
{
    /**
     * @param JwtInfo $jwt_info
     * @param string $access_token
     * @return AccessTokenInfo
     * @throws ExpireTokenException
     * @throws InvalidJwtSignatureException
     */
    public static function introspect(JwtInfo $jwt_info, string $access_token): AccessTokenInfo
    {
        $introspector = new JwtIntrospector($jwt_info, $access_token);
        $result = $introspector->introspect();
        try {
            return AccessTokenInfo::fromObject($result);
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtSignatureException();
        }
    }
}
