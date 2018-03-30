<?php
namespace Ridibooks\OAuth2Resource\Grant\Exception;


class OAuthFailureException extends GrantException
{
    /**
     * @var string
     */
    private $error_code;

    /**
     * @var string
     */
    private $description;

    /**
     * @var string
     */
    private $error_uri;

    /**
     * OAuthFailureException constructor.
     * @param string $error_code
     * @param string $description
     * @param string $error_uri
     */
    public function __construct(string $error_code, string $description, string $error_uri)
    {
        $this->error_code = $error_code;
        $this->description = $description;
        $this->error_uri = $error_uri;
    }

    /**
     * @return string
     */
    public function getErrorCode(): string
    {
        return $this->error_code;
    }

    /**
     * @return string
     */
    public function getDescription(): string
    {
        return $this->description;
    }

    /**
     * @return string
     */
    public function getErrorUri(): string
    {
        return $this->error_uri;
    }
}
