<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2\Symfony\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\BadResponseException;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Exception\UserNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class DefaultUserProvider implements UserProviderInterface
{
    /**
     * @param JwtToken $token
     * @param Request $request
     * @param OAuth2ServiceProvider $oauth2_service_provider
     * @return User
     * @throws AuthorizationException
     * @throws TokenNotFoundException
     * @throws UserNotFoundException
     */
    public function getUser(JwtToken $token, Request $request, OAuth2ServiceProvider $oauth2_service_provider): User
    {
        $access_token = $request->cookies->get(AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY);
        if (is_null($access_token)) {
            throw new TokenNotFoundException();
        }

        $cookie_jar = CookieJar::fromArray(
            [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token],
            $oauth2_service_provider->getConfigs()['token_cookie_domain']
        );

        try {
            $client = new Client();
            $response = $client->get(
                $oauth2_service_provider->getConfigs()['user_info_url'],
                [
                    'cookies' => $cookie_jar,
                    'headers' => ['Accept' => 'application/json']
                ]
            );
            $content = $response->getBody()->getContents();
        } catch (BadResponseException $e) {
            $status = $e->getResponse()->getStatusCode();
            if ($status === Response::HTTP_UNAUTHORIZED) {
                throw new AuthorizationException('Unauthorized access token');
            }
            if ($status === Response::HTTP_NOT_FOUND) {
                throw new UserNotFoundException();
            }
            throw new AuthorizationException($e->getMessage());
        } catch (\Exception $e) {
            throw new AuthorizationException($e->getMessage());
        }

        return new User($content);
    }
}
