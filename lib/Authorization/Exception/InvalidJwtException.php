<?php declare(strict_types=1);
namespace Ridibooks\OAuth2\Authorization\Exception;

use Throwable;

class InvalidJwtException extends AuthorizationException
{
    public function __construct(Throwable $previous = null)
    {
        parent::__construct('Invalid JWT', 0, $previous);
    }
}
