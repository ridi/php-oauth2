<?php
namespace Ridibooks\OAuth2Resource\RidiSymfonyOAuth2Resource;

use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\DataTransferObject\AccessTokenInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\DataTransferObject\JwtInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Helper\JwtIntrospectHelper;
use Ridibooks\OAuth2Resource\RidiOAuth2\Resource\ScopeChecker;
use Ridibooks\OAuth2Resource\RidiSymfonyOAuth2Resource\Exception\AccessTokenDoesNotExistException;
use Ridibooks\OAuth2Resource\RidiSymfonyOAuth2Resource\Exception\ExpireTokenException;
use Ridibooks\OAuth2Resource\RidiSymfonyOAuth2Resource\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2Resource\RidiSymfonyOAuth2Resource\Exception\InvalidScopeException;
use Ridibooks\OAuth2Resource\RidiSymfonyOAuth2Resource\Exception\WrongInstanceException;
use Symfony\Component\HttpFoundation\Request;

class MiddlewareFactory
{
    /**
     * @param JwtInfo $jwt_info
     * @return Callable
     */
    public static function introspect(JwtInfo $jwt_info): Callable
    {
        /**
         * @param Request $request
         * @return null
         * @throws AccessTokenDoesNotExistException
         * @throws InvalidJwtSignatureException
         * @throws ExpireTokenException
         */
        return function (Request $request) use ($jwt_info) {
            $access_token = $request->cookies->get(ResourceConstants::ACCESS_TOKEN_KEY);
            if ($access_token === null) {
                throw new AccessTokenDoesNotExistException();
            }

            try {
                $access_token_info = JwtIntrospectHelper::introspect($jwt_info, $access_token);
            } catch (\Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Exception\InvalidJwtSignatureException $e) {
                throw new InvalidJwtSignatureException();
            } catch (\Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Exception\ExpireTokenException $e) {
                throw new ExpireTokenException();
            }

            $request->attributes->set(ResourceConstants::ACCESS_TOKEN_INFO_KEY, $access_token_info);
            return null;
        };
    }

    /**
     * @param array $require_scopes
     * @return Callable
     */
    public static function checkScope(array $require_scopes): Callable
    {
        /**
         * @param Request $request
         * @return null
         * @throws AccessTokenDoesNotExistException
         * @throws InvalidScopeException
         * @throws WrongInstanceException
         */
        return function (Request $request) use ($require_scopes) {
            $access_token_info = $request->attributes->get(ResourceConstants::ACCESS_TOKEN_INFO_KEY);
            if ($access_token_info === null) {
                throw new AccessTokenDoesNotExistException();
            }

            if (!($access_token_info instanceof AccessTokenInfo)) {
                throw new WrongInstanceException();
            }

            $user_scope = $access_token_info->getScope();
            if (!ScopeChecker::check($require_scopes, $user_scope)) {
                throw new InvalidScopeException();
            }

            return null;
        };
    }
}