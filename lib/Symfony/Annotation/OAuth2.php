<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2\Symfony\Annotation;

use Ridibooks\OAuth2\Symfony\Handler\OAuth2ExceptionHandlerInterface;
use Ridibooks\OAuth2\Symfony\Provider\DefaultUserProvider;
use Ridibooks\OAuth2\Symfony\Provider\UserProviderInterface;
use Ridibooks\OAuth2\Symfony\Subscriber\OAuth2Middleware;

/**
 * Annotation class for @OAuth2().
 *
 * Annotated classes or methods with annotation @OAuth2 use OAuth2Middleware.
 * @see OAuth2Middleware
 *
 * @Annotation
 * @Target({"CLASS", "METHOD"})
 */
class OAuth2
{
    /** @var string[] */
    private $scopes;

    /** @var UserProviderInterface */
    private $user_provider;

    /** @var OAuth2ExceptionHandlerInterface */
    private $exception_handler;

    /**
     * @param array $data
     */
    public function __construct(array $data)
    {
        $this->setScopes($data);
        $this->setUserProvider($data);
        $this->setExceptionHandler($data);
    }

    /**
     * @return string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return UserProviderInterface
     */
    public function getUserProvider(): UserProviderInterface
    {
        return $this->user_provider;
    }

    /**
     * @return OAuth2ExceptionHandlerInterface
     */
    public function getExceptionHandler(): OAuth2ExceptionHandlerInterface
    {
        return $this->exception_handler;
    }

    /**
     * @param array $data
     */
    private function setScopes(array $data)
    {
        if (isset($data['scopes']) && is_array($data['scopes'])) {
            $this->scopes = $data['scopes'];
        } else {
            $this->scopes = [];
        }
    }

    /**
     * @param array $data
     */
    private function setUserProvider(array $data)
    {
        if (isset($data['user_provider'])) {
            $user_provider_class = $data['user_provider'];

            try {
                $reflection_class = new \ReflectionClass($user_provider_class);
            } catch (\Exception $e) {
                throw new \InvalidArgumentException('The user_provider is invalid.');
            }

            $user_provider_interface_class = UserProviderInterface::class;
            if (!in_array($user_provider_interface_class, $reflection_class->getInterfaceNames())) {
                throw new \InvalidArgumentException("The user_provider must implement {$user_provider_interface_class}.");
            }

            $this->user_provider = new $user_provider_class();
        } else {
            $this->user_provider = new DefaultUserProvider();
        }
    }

    /**
     * @param array $data
     */
    private function setExceptionHandler(array $data)
    {
        if (!isset($data['exception_handler'])) {
            throw new \InvalidArgumentException('The exception_handler is required.');
        }

        try {
            $exception_handler_class = $data['exception_handler'];
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

        $this->exception_handler = new $exception_handler_class();
    }
}
