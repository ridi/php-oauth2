<?php declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Silex;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Ridibooks\OAuth2\Grant\Granter;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Ridibooks\OAuth2\Silex\Handler\IgnoreExceptionHandler;
use Ridibooks\OAuth2\Silex\Handler\LoginForcedExceptionHandler;
use Ridibooks\OAuth2\Silex\Handler\LoginRequiredExceptionHandler;
use Ridibooks\OAuth2\Silex\Provider\DefaultUserProvider;
use Ridibooks\OAuth2\Silex\Provider\OAuth2ServiceProvider;
use Ridibooks\Test\OAuth2\Common\TestUserProvider;
use Ridibooks\Test\OAuth2\Common\TokenConstant;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class OAuth2MiddlewareFactoryTest extends TestCase
{
    private $authorization_url = 'https://account.ridibooks.com/oauth2/authorize/';
    private $token_url = 'https://account.ridibooks.com/oauth2/token/';

    private function registerProvider($options = [])
    {
        $app = new Application();
        $options = array_merge([
            OAuth2ProviderKeyConstant::CLIENT_ID => TokenConstant::CLIENT_ID,
            OAuth2ProviderKeyConstant::CLIENT_SECRET => TokenConstant::CLIENT_SECRET,
            OAuth2ProviderKeyConstant::AUTHORIZE_URL => $this->authorization_url,
            OAuth2ProviderKeyConstant::TOKEN_URL => $this->token_url,
            OAuth2ProviderKeyConstant::JWT_ALGORITHM => TokenConstant::ALGORITHM,
            OAuth2ProviderKeyConstant::JWT_SECRET => TokenConstant::SECRET,
            OAuth2ProviderKeyConstant::DEFAULT_USER_PROVIDER => new TestUserProvider(),
            OAuth2ProviderKeyConstant::DEFAULT_EXCEPTION_HANDLER => new LoginRequiredExceptionHandler(),
        ], $options);
        $app->register(new OAuth2ServiceProvider(), $options);
        return $app;
    }

    private function getDefaultUserProvider(GuzzleResponse $expected_response)
    {
        $mock = new MockHandler([$expected_response]);
        $handler = HandlerStack::create($mock);

        return new DefaultUserProvider('/', ['handler' => $handler]);
    }

    public function testLoadUser()
    {
        $app = $this->registerProvider();

        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize([], new IgnoreExceptionHandler()));

        $access_token = TokenConstant::TOKEN_VALID;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $app->handle($req);

        $this->assertEquals(TokenConstant::USER_IDX, $app[OAuth2ProviderKeyConstant::USER]->id);
    }

    public function testExpiredTokenWithLoginForcedExceptionHandler()
    {
        $app = $this->registerProvider();
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize([], new LoginForcedExceptionHandler()));

        $access_token = TokenConstant::TOKEN_EXPIRED;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_FOUND, $resp->getStatusCode());

        $state = ($resp->headers->getCookies()[0])->getValue();
        /** @var Granter $granter */
        $granter = $app[OAuth2ProviderKeyConstant::GRANTER];
        $authorize_url = $granter->authorize($state, $req->getUri());

        $this->assertEquals($authorize_url, $resp->headers->get('location'));
    }

    public function testExpiredTokenWithLoginRequiredExceptionHandler()
    {
        $app = $this->registerProvider();
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize());

        $access_token = TokenConstant::TOKEN_EXPIRED;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $resp->getStatusCode());
    }

    public function testInvalidPayloadToken()
    {
        $app = $this->registerProvider();
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize());

        $access_token = TokenConstant::TOKEN_INVALID_PAYLOAD;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $resp->getStatusCode());
    }

    public function testInvalidSignatureToken()
    {
        $app = $this->registerProvider();
        $app->get('/', function () {
        })
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize());

        $access_token = TokenConstant::TOKEN_INVALID_SIGNATURE;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $resp->getStatusCode());
    }

    public function testInvalidScopeTokenWithLoginForcedExceptionHandler()
    {
        $app = $this->registerProvider();
        $app['debug'] = true;
        $app->get('/', function () {
        })
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(['test_scope'], new LoginForcedExceptionHandler()));

        $access_token = TokenConstant::TOKEN_HAS_NO_SCOPE;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_FOUND, $resp->getStatusCode());

        $state = ($resp->headers->getCookies()[0])->getValue();
        /** @var Granter $granter */
        $granter = $app[OAuth2ProviderKeyConstant::GRANTER];
        $authorize_url = $granter->authorize($state, $req->getUri(), ['test_scope']);

        $this->assertEquals($authorize_url, $resp->headers->get('location'));
    }

    public function testInvalidScopeTokenWithLoginRequiredExceptionHandler()
    {
        $app = $this->registerProvider();
        $app['debug'] = true;
        $app->get('/', function () {
        })
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(['test_scope'], new LoginRequiredExceptionHandler()));

        $access_token = TokenConstant::TOKEN_HAS_NO_SCOPE;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_FORBIDDEN, $resp->getStatusCode());
    }

    public function testUnknownUserToken()
    {
        $app = $this->registerProvider();
        $app->get('/', function () {
        })
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize());

        $access_token = TokenConstant::TOKEN_UNKNOWN_USER;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $resp->getStatusCode());
    }

    public function testDefaultUserProvider()
    {
        // Initialize DefaultUserProvider Mock
        $body = [
            "result" => [
                "id" => TokenConstant::USERNAME,
                "idx" => TokenConstant::USER_IDX,
                "is_verified_adult" => true,
            ],
            "message" => "정상적으로 완료되었습니다."
        ];
        $response = new GuzzleResponse(200, [], json_encode($body));
        $userProvider = $this->getDefaultUserProvider($response);

        // Initialize App
        $app = $this->registerProvider();
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize([], new IgnoreExceptionHandler(), $userProvider));

        $access_token = TokenConstant::TOKEN_VALID;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $app->handle($req);

        $this->assertEquals(TokenConstant::USER_IDX, $app[OAuth2ProviderKeyConstant::USER]->idx);
        $this->assertEquals(TokenConstant::USERNAME, $app[OAuth2ProviderKeyConstant::USER]->id);
    }

    public function testDefaultUserProviderUserNotFound()
    {
        // Initialize DefaultUserProvider Mock
        $body = [
            'code' => 'LOGIN_REQUIRED',
            'message' => '로그인이 필요합니다.'
        ];
        $response = new GuzzleResponse(401, [], json_encode($body));
        $userProvider = $this->getDefaultUserProvider($response);

        // Initialize App
        $app = $this->registerProvider();
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize([], new LoginRequiredExceptionHandler(), $userProvider));

        $access_token = TokenConstant::TOKEN_VALID;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $resp->getStatusCode());
    }
}
