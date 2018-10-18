<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2\Symfony\Annotation;

use Ridibooks\OAuth2\Symfony\Handler\OAuth2ExceptionHandlerInterface;
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

    /** @var null|string */
    private $user_provider;

    /** @var null|string */
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
     * @return null|string
     */
    public function getUserProvider(): ?string
    {
        return $this->user_provider;
    }

    /**
     * @return null|string
     */
    public function getExceptionHandler(): ?string
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
            $this->user_provider = $data['user_provider'];
        }
    }

    /**
     * @param array $data
     */
    private function setExceptionHandler(array $data)
    {
        if (isset($data['exception_handler'])) {
            $this->exception_handler = $data['exception_handler'];
        }
    }
}
