<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2\Symfony\Subscriber;

use Doctrine\Common\Annotations\CachedReader;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Symfony\Annotation\OAuth2;
use Ridibooks\OAuth2\Symfony\Handler\OAuth2ExceptionHandlerInterface;
use Ridibooks\OAuth2\Symfony\Provider\OAuth2ServiceProvider;
use Ridibooks\OAuth2\Symfony\Provider\User;
use Ridibooks\OAuth2\Symfony\Provider\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class OAuth2Middleware implements EventSubscriberInterface
{
    /** @var CachedReader */
    private $annotation_reader;

    /** @var OAuth2ServiceProvider */
    private $oauth2_service_provider;

    /** @var User */
    private $user;

    /**
     * @param CachedReader $annotation_reader
     * @param OAuth2ServiceProvider $oauth2_service_provider
     */
    public function __construct(CachedReader $annotation_reader, OAuth2ServiceProvider $oauth2_service_provider)
    {
        $this->annotation_reader = $annotation_reader;
        $this->oauth2_service_provider = $oauth2_service_provider;
    }

    /**
     * @return array
     */
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::CONTROLLER => 'onKernelController',
        ];
    }

    /**
     * @param FilterControllerEvent $event
     * @throws \ReflectionException
     */
    public function onKernelController(FilterControllerEvent $event): void
    {
        if (!is_array($event->getController())) {
            return;
        }

        [$controller, $method_name] = $event->getController();
        $annotation = $this->getAnnotation($controller, $method_name);
        if (is_null($annotation)) {
            return;
        }

        try {
            $token = $this->oauth2_service_provider->getAuthorizer()->authorize(
                $event->getRequest(),
                $annotation->getScopes()
            );
            $this->user = self::getUserProvider($annotation)->getUser(
                $token,
                $event->getRequest(),
                $this->oauth2_service_provider
            );
        } catch (AuthorizationException $e) {
            $response = self::getExceptionHandler($annotation)->handle(
                $e,
                $event->getRequest(),
                $this->oauth2_service_provider
            );
            if ($response instanceof Response) {
                $event->setController(function () use ($response) {
                    return $response;
                });
            }
        }

        return;
    }

    /**
     * @return User
     */
    public function getUser(): User
    {
        return $this->user;
    }

    /**
     * @param $controller
     * @param string $method_name
     * @return null|OAuth2
     * @throws \ReflectionException
     */
    private function getAnnotation($controller, string $method_name): ?OAuth2
    {
        $reflection_class = new \ReflectionClass($controller);
        $reflection_method = $reflection_class->getMethod($method_name);

        return $this->annotation_reader->getMethodAnnotation($reflection_method, OAuth2::class);
    }

    /**
     * @param OAuth2 $annotation
     * @return UserProviderInterface
     */
    private function getUserProvider(OAuth2 $annotation): UserProviderInterface
    {
        if (is_null($annotation->getUserProvider())) {
            $user_provider_class = $this->oauth2_service_provider->getConfigs()['default_user_provider'];
        } else {
            $user_provider_class = $annotation->getUserProvider();
        }

        try {
            $reflection_class = new \ReflectionClass($user_provider_class);
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('The user_provider is invalid.');
        }

        $user_provider_interface_class = UserProviderInterface::class;
        if (!in_array($user_provider_interface_class, $reflection_class->getInterfaceNames())) {
            throw new \InvalidArgumentException(
                "The user_provider must implement {$user_provider_interface_class}."
            );
        }

        return new $user_provider_class();
    }

    /**
     * @param OAuth2 $annotation
     * @return OAuth2ExceptionHandlerInterface
     */
    private function getExceptionHandler(OAuth2 $annotation): OAuth2ExceptionHandlerInterface
    {
        if (is_null($annotation->getExceptionHandler())) {
            $exception_handler_class = $this->oauth2_service_provider->getConfigs()['default_exception_handler'];
        } else {
            $exception_handler_class = $annotation->getExceptionHandler();
        }

        try {
            $reflection_class = new \ReflectionClass($exception_handler_class);
        } catch (\Exception $e) {
            throw new \InvalidArgumentException('The exception_handler is invalid.');
        }

        $exception_handler_interface_class = OAuth2ExceptionHandlerInterface::class;
        if (!in_array($exception_handler_interface_class, $reflection_class->getInterfaceNames())) {
            throw new \InvalidArgumentException(
                "The exception_handler must implement {$exception_handler_interface_class}."
            );
        }

        return new $exception_handler_class();
    }
}
