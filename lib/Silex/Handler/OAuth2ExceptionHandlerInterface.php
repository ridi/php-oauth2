<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Handler;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

interface OAuth2ExceptionHandlerInterface
{
    /**
     * @param AuthorizationException $e
     * @param Request $request
     * @param Application $app
     * @return Response | null
     */
    public function handle(AuthorizationException $e, Request $request, Application $app);
}
