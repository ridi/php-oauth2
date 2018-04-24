<?php declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Common;

use Ridibooks\OAuth2\Authorization\Exception\UserNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Silex\Provider\UserProviderInterface;

class TestUserProvider implements UserProviderInterface
{
    /**
     * @param JwtToken $token
     * @return mixed|\stdClass
     * @throws UserNotFoundException
     */
    public function getUser(JwtToken $token)
    {
        if ($token->getSubject() === 'unknown') {
            throw new UserNotFoundException();
        }
        $user = new \stdClass();
        $user->id = $token->getUIdx();
        return $user;
    }
}
