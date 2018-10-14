<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2\Symfony\Provider;

use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Symfony\Component\HttpFoundation\Request;

interface UserProviderInterface
{
    /**
     * @param JwtToken $token
     * @param Request $request
     * @param OAuth2ServiceProvider $oauth2_service_provider
     * @return User
     */
    public function getUser(JwtToken $token, Request $request, OAuth2ServiceProvider $oauth2_service_provider): User;
}
