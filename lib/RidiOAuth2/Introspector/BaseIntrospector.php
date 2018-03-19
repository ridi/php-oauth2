<?php
namespace Ridibooks\OAuth2Resource\RidiOAuth2\Introspector;

use stdClass;

abstract class BaseIntrospector
{
    /**
     * @var string
     */
    protected $access_token;
    /**
     * @var string
     */
    protected $token_type_hint;

    /**
     * @param string $access_token
     * @param string $token_type_hint
     */
    public function __construct(string $access_token, string $token_type_hint)
    {
        $this->access_token = $access_token;
        $this->token_type_hint = $token_type_hint;
    }

    /**
     * @return string
     */
    public function getAccessToken(): string
    {
        return $this->access_token;
    }

    /**
     * @return string
     */
    public function getTokenTypeHint(): string
    {
        return $this->token_type_hint;
    }

    /**
     * @return stdClass
     */
    abstract public function introspect(): stdClass;
}
