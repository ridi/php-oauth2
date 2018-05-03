<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Provider;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

interface UserProviderInterface
{
    /**
     * @param JwtToken $token
     * @param Request $request
     * @param Application $app
     * @return mixed
     * @throws AuthorizationException
     */
    public function getUser(JwtToken $token, Request $request, Application $app);
}
