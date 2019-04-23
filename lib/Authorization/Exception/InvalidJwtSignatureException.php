<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Authorization\Exception;

class InvalidJwtSignatureException extends InvalidJwtException
{
    public function __construct()
    {
        parent::__construct('Signature verification failed');
    }
}
