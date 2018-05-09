<?php declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Common;

use Ridibooks\OAuth2\Authorization\Exception\UserNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Silex\Provider\UserProviderInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

class TestUserProvider implements UserProviderInterface
{
    /**
     * @param JwtToken $token
     * @param Request $request
     * @param Application $app
     * @return mixed|\stdClass
     * @throws UserNotFoundException
     */
    public function getUser(JwtToken $token, Request $request, Application $app)
    {
        if ($token->getSubject() === 'unknown') {
            throw new UserNotFoundException();
        }
        $user = new \stdClass();
        $user->id = $token->getUIdx();
        return $user;
    }
}
