<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Provider;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;

interface UserProviderInterface
{
    /**
     * @param JwtToken $token
     * @return mixed
     * @throws AuthorizationException
     */
    public function getUser(JwtToken $token);
}
