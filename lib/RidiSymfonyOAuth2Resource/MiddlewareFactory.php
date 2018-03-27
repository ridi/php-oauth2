<?php
namespace Ridibooks\OAuth2Resource\RidiSymfonyOAuth2Resource;

use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\DataTransferObject\AccessTokenInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\DataTransferObject\JwtInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Exception\ExpireTokenException;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Helper\JwtIntrospectHelper;
use Ridibooks\OAuth2Resource\RidiOAuth2\Resource\ScopeChecker;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

class MiddlewareFactory
{
    /**
     * @param bool $is_required
     * @return null
     * @throws HttpException
     */
    private static function assertAuthorizeRequired(bool $is_required)
    {
        if ($is_required) {
            throw new HttpException(Response::HTTP_UNAUTHORIZED);
        } else {
            return null;
        }
    }

    /**
     * @param JwtInfo $jwt_info
     * @param bool $is_required
     * @return Callable
     */
    public static function introspect(JwtInfo $jwt_info, bool $is_required = false): Callable
    {
        /**
         * @param Request $request
         * @return null
         * @throws HttpException
         */
        return function (Request $request) use ($jwt_info, $is_required) {
            $access_token = $request->cookies->get(ResourceConstants::ACCESS_TOKEN_KEY);

            if ($access_token === null) {
                return MiddlewareFactory::assertAuthorizeRequired($is_required);
            }

            try {
                $access_token_info = JwtIntrospectHelper::introspect($jwt_info, $access_token);
            } catch (InvalidJwtSignatureException $e) {
                return MiddlewareFactory::assertAuthorizeRequired($is_required);
            } catch (ExpireTokenException $e) {
                return MiddlewareFactory::assertAuthorizeRequired($is_required);
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
         * @throws HttpException
         */
        return function (Request $request) use ($require_scopes) {
            $access_token_info = $request->attributes->get(ResourceConstants::ACCESS_TOKEN_INFO_KEY);
            if ($access_token_info === null) {
                throw new HttpException(Response::HTTP_UNAUTHORIZED);
            }

            if (!($access_token_info instanceof AccessTokenInfo)) {
                throw new HttpException(Response::HTTP_INTERNAL_SERVER_ERROR);
            }

            $user_scope = $access_token_info->getScope();
            if (!ScopeChecker::check($require_scopes, $user_scope)) {
                throw new HttpException(Response::HTTP_FORBIDDEN);
            }

            return null;
        };
    }
}