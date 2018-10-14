<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Symfony;

use Ridibooks\OAuth2\Symfony\Annotation\OAuth2;
use Ridibooks\OAuth2\Symfony\Provider\OAuth2ServiceProvider;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class TestController extends Controller
{
    /** @var OAuth2ServiceProvider */
    private $oauth2_service_provider;

    /**
     * @param OAuth2ServiceProvider $oauth2_service_provider
     */
    public function __construct(OAuth2ServiceProvider $oauth2_service_provider)
    {
        $this->oauth2_service_provider = $oauth2_service_provider;
    }

    /**
     * @Route("/oauth2", methods={"GET"})
     * @OAuth2(exception_handler="Ridibooks\Test\OAuth2\Symfony\TestExceptionHandler")
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function normal(Request $request): JsonResponse
    {
        $user = $this->oauth2_service_provider->getMiddleware()->getUser();

        return new JsonResponse([
            'u_idx' => $user->getUidx(),
            'u_id' => $user->getUid()
        ]);
    }

    /**
     * @Route("/oauth2-scope-test", methods={"GET"})
     * @OAuth2(
     *   scopes={"test_scope"},
     *   exception_handler="Ridibooks\Test\OAuth2\Symfony\TestExceptionHandler"
     * )
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function scopeTest(Request $request): JsonResponse
    {
        $user = $this->oauth2_service_provider->getMiddleware()->getUser();

        return new JsonResponse([
            'u_idx' => $user->getUidx(),
            'u_id' => $user->getUid()
        ]);
    }
}
