<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Symfony;

use AspectMock\Test as Test;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Ridibooks\OAuth2\Symfony\Provider\DefaultUserProvider;
use Ridibooks\OAuth2\Symfony\Provider\User;
use Ridibooks\Test\OAuth2\Common\TokenConstant;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class OAuth2MiddlewareTest extends WebTestCase
{
    /**
     * @dataProvider tokenProvider
     *
     * @param string $token
     * @param int $http_status_code
     * @throws AuthorizationException
     */
    public function testMiddleware(string $token, int $http_status_code)
    {
        if ($http_status_code === Response::HTTP_OK) {
            Test::double(
                DefaultUserProvider::class,
                [
                    'getUser' => new User(json_encode([
                        "result" => [
                            "id" => TokenConstant::USERNAME,
                            "idx" => TokenConstant::USER_IDX,
                            "email" => 'oauth2-test@ridi.com',
                            "is_verified_adult" => true,
                        ],
                        "message" => "정상적으로 완료되었습니다."
                    ]))
                ]
            );
        }

        $client = self::createClient();
        $client->getCookieJar()->set(new Cookie(AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY, $token));
        $client->request(
            Request::METHOD_GET,
            $token === TokenConstant::TOKEN_HAS_NO_SCOPE ? '/oauth2-scope-test' : '/oauth2'
        );

        $response_status_code = $client->getResponse()->getStatusCode();
        $this->assertSame($http_status_code, $response_status_code);

        Test::clean(DefaultUserProvider::class);
    }

    /**
     * @return array
     */
    public function tokenProvider(): array
    {
        return [
            [TokenConstant::TOKEN_VALID, Response::HTTP_OK],
            [TokenConstant::TOKEN_EXPIRED, Response::HTTP_UNAUTHORIZED],
            [TokenConstant::TOKEN_EMPTY, Response::HTTP_UNAUTHORIZED],
            [TokenConstant::TOKEN_INVALID_PAYLOAD, Response::HTTP_UNAUTHORIZED],
            [TokenConstant::TOKEN_INVALID_SIGNATURE, Response::HTTP_UNAUTHORIZED],
            [TokenConstant::TOKEN_HAS_NO_SCOPE, Response::HTTP_FORBIDDEN]
        ];
    }

    /**
     * @param array $options
     * @return TestKernel
     */
    protected static function createKernel(array $options = []): TestKernel
    {
        return new TestKernel('test', false);
    }
}
