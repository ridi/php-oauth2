<?php declare(strict_types=1);
namespace Ridibooks\OAuth2Resource\Symfony\Middleware;

use Ridibooks\OAuth2Resource\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2Resource\Authorization\Token\RidiTokenInfo;
use Ridibooks\OAuth2Resource\Authorization\Validator\JwtInfo;
use Ridibooks\OAuth2Resource\Authorization\Validator\RidiTokenValidator;
use Ridibooks\OAuth2Resource\Constant\AccessTokenConstant;
use Ridibooks\OAuth2Resource\Symfony\Exception\AccessTokenDoesNotExistException;
use Ridibooks\OAuth2Resource\Symfony\Exception\ExpiredTokenException;
use Ridibooks\OAuth2Resource\Symfony\Exception\InvalidRequestException;
use Ridibooks\OAuth2Resource\Symfony\Exception\InvalidTokenException;
use Ridibooks\OAuth2Resource\Symfony\Exception\InsufficientScopeException;
use Symfony\Component\HttpFoundation\Request;

class RidiOAuth2MiddlewareFactory
{
    private static function setTokenToRequest(Request $request, RidiTokenInfo $token)
    {
        $request->attributes->set(AccessTokenConstant::ACCESS_TOKEN_INFO_KEY, $token);
    }

    private static function getTokenFromRequest(Request $request)
    {
        return $request->attributes->get(AccessTokenConstant::ACCESS_TOKEN_INFO_KEY);
    }

    /**
     * Get and verify access token
     * @param JwtInfo $jwt_info
     * @return Callable
     */
    public static function introspect(JwtInfo $jwt_info): callable
    {
        /**
         * @param Request $request
         * @throws InvalidRequestException
         */
        return function (Request $request) use ($jwt_info) {
            $access_token = $request->cookies->get(AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY);
            if ($access_token === null) {
                return;
            }

            $token_validator = new RidiTokenValidator($jwt_info);
            try {
                $ridi_token = $token_validator->validateToken($access_token);
            } catch (InvalidJwtException $e) {
                throw new InvalidRequestException($e->getMessage());
            }
            self::setTokenToRequest($request, $ridi_token);
        };
    }

    /**
     * Ensure authenticated
     * @return callable
     */
    public static function loginRequired(): callable
    {
        /**
         * @param Request $request
         * @throws AccessTokenDoesNotExistException
         * @throws InvalidTokenException
         * @throws ExpiredTokenException
         */
        return function (Request $request) {
            $token = self::getTokenFromRequest($request);
            if ($token === null || !($token instanceof RidiTokenInfo)) {
                throw new AccessTokenDoesNotExistException();
            }
            if (!$token->isValid()) {
                throw new InvalidTokenException();
            }
            if ($token->isExpired()) {
                throw new ExpiredTokenException();
            }
        };
    }

    /**
     * Check required scopes are satisfied
     * @param array $require_scopes
     * @return Callable
     */
    public static function checkScope(array $require_scopes): callable
    {
        /**
         * @param Request $request
         * @throws AccessTokenDoesNotExistException
         * @throws InsufficientScopeException
         */
        return function (Request $request) use ($require_scopes) {
            $token = self::getTokenFromRequest($request);
            if ($token === null || !($token instanceof RidiTokenInfo)) {
                throw new AccessTokenDoesNotExistException();
            }

            if (!$token->hasScopes($require_scopes)) {
                throw new InsufficientScopeException();
            }
        };
    }
}
