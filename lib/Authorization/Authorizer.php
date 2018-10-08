<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization;

use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InsufficientScopeException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Ridibooks\OAuth2\Grant\DataTransferObject\TokenData;
use Ridibooks\OAuth2\Grant\Granter;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Silex\Application;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Authorizer
{
    /** @var JwtTokenValidator */
    private $token_validator;
    /** @var array */
    private $default_scopes;

    public function __construct(JwtTokenValidator $token_validator, array $default_scopes = [])
    {
        $this->token_validator = $token_validator;
        $this->default_scopes = $default_scopes;
    }

    public function authorize(Request $request, Application $app, array $required_scopes = [], bool $use_refreshing_access_token = false): JwtToken
    {
        $access_token = $request->cookies->get(AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY);

        // 1. Validate access_token
        try {
            $token = $this->token_validator->validateToken($access_token);
        } catch (TokenNotFoundException | ExpiredTokenException $e) {
            $refresh_token = $request->cookies->get(AccessTokenConstant::REFRESH_TOKEN_COOKIE_KEY);

            // Refresh access token if requested
            if ($use_refreshing_access_token && !empty($refresh_token)) {
                /** @var Granter $granter */
                $granter = $app[OAuth2ProviderKeyConstant::GRANTER];

                $token_data = $granter->refresh($refresh_token);
                $token = $this->token_validator->validateToken($token_data->getAccessToken()->getToken());

                $app->after($this->setTokenCookiesMiddleware($token_data));
            } else {
                throw $e;
            }
        }

        // 2. Check scope
        if (empty($required_scopes)) {
            $required_scopes = $this->default_scopes;
        }
        if (!empty($required_scopes) && !$token->hasScopes($required_scopes)) {
            throw new InsufficientScopeException($required_scopes);
        }

        return $token;
    }

    /**
     * Set-Cookie Middleware: access token(ridi-at), refresh token(ridi-rt)
     *
     * @param TokenData $token_data
     * @return \Closure
     */
    private function setTokenCookiesMiddleware(TokenData $token_data)
    {
        return function (Request $request, Response $response, Application $app) use ($token_data) {
            $access_token_cookie = new Cookie(
                AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY,
                $token_data->getAccessToken()->getToken(),
                time() + $token_data->getAccessToken()->getExpiresIn(),
                '/',
                $app[OAuth2ProviderKeyConstant::TOKEN_COOKIE_DOMAIN],
                true,
                true
            );
            $response->headers->setCookie($access_token_cookie);

            $refresh_token_cookie = new Cookie(
                AccessTokenConstant::REFRESH_TOKEN_COOKIE_KEY,
                $token_data->getRefreshToken()->getToken(),
                time() + $token_data->getRefreshToken()->getExpiresIn(),
                '/',
                $app[OAuth2ProviderKeyConstant::TOKEN_COOKIE_DOMAIN],
                true,
                true
            );
            $response->headers->setCookie($refresh_token_cookie);
        };
    }
}
