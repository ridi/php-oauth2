<?php declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Common;


use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Silex\Provider\UserProviderInterface;

class TestUserProvider implements UserProviderInterface
{
    public function getUser(JwtToken $token)
    {
        $user = new \stdClass();
        $user->id = $token->getUIdx();
        return $user;
    }
}
