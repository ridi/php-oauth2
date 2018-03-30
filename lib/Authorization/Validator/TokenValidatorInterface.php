<?php

namespace Ridibooks\OAuth2Resource\Authorization\Validator;

use Ridibooks\OAuth2Resource\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2Resource\Authorization\Token\BaseTokenInfo;

interface TokenValidatorInterface
{
    /**
     * @param string $access_token
     * @return BaseTokenInfo
     * @throws InvalidJwtException
     */
    public function validateToken(string $access_token): BaseTokenInfo;
}
