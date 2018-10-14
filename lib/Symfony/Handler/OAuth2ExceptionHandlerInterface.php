<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2\Symfony\Handler;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Symfony\Provider\OAuth2ServiceProvider;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

interface OAuth2ExceptionHandlerInterface
{
    /**
     * @param AuthorizationException $e
     * @param Request $request
     * @param OAuth2ServiceProvider $oauth2_service_provider
     * @return null|Response
     */
    public function handle(
        AuthorizationException $e,
        Request $request,
        OAuth2ServiceProvider $oauth2_service_provider
    ): ?Response;
}
