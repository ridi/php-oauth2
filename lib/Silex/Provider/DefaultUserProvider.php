<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Silex\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\BadResponseException;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Exception\UserNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class DefaultUserProvider implements UserProviderInterface
{
    const TOKEN_COOKIE_DOMAIN = '.ridibooks.com';
    private $user_info_url;
    private $http_options;

    public function __construct(string $user_info_url, array $http_options = [])
    {
        $this->user_info_url = $user_info_url;
        $this->http_options = $http_options;
    }

    public function getUser(JwtToken $token, Request $request, Application $app)
    {
        $access_token = $request->cookies->get(AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY);
        if ($access_token === null) {
            throw new TokenNotFoundException();
        }

        $cookie_jar = CookieJar::fromArray([AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token],
            self::TOKEN_COOKIE_DOMAIN);

        $client = new Client($this->http_options);
        try {
            $response = $client->get($this->user_info_url, ['cookies' => $cookie_jar]);
            $content = $response->getBody()->getContents();
        } catch (BadResponseException $e) {
            $status = $e->getResponse()->getStatusCode();
            if ($status === Response::HTTP_UNAUTHORIZED) {
                throw new AuthorizationException('Unauthorized access_token');
            }
            if ($status === Response::HTTP_NOT_FOUND) {
                throw new UserNotFoundException();
            }
            throw new AuthorizationException($e->getMessage());
        } catch (\Exception $e) {
            throw new AuthorizationException($e->getMessage());
        }

        $json = json_decode($content);
        if ($json === null || !isset($json->result)) {
            throw new AuthorizationException('Invalid JSON user info');
        }
        return $json->result;
    }
}
