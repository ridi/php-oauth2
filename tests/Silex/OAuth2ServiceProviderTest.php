<?php declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Silex;


use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Ridibooks\OAuth2\Grant\Grant;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Ridibooks\OAuth2\Silex\Handler\IgnoreExceptionHandler;
use Ridibooks\OAuth2\Silex\Handler\LoginForcedExceptionHandler;
use Ridibooks\OAuth2\Silex\Handler\LoginRequiredExceptionHandler;
use Ridibooks\OAuth2\Silex\Provider\OAuth2ServiceProvider;
use Ridibooks\Test\OAuth2\Common\TestUserProvider;
use Ridibooks\Test\OAuth2\Common\TokenConstant;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class OAuth2ServiceProviderTest extends TestCase
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
            OAuth2ProviderKeyConstant::JWT_SECRET => TokenConstant::SECRET
        ], $options);
        $app->register(new OAuth2ServiceProvider(), $options);
        return $app;
    }

    public function testLoadUser()
    {
        $app = $this->registerProvider();

        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(new IgnoreExceptionHandler(), new TestUserProvider()));

        $access_token = TokenConstant::TOKEN_VALID;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $app->handle($req);

        $this->assertEquals(TokenConstant::USER_IDX, $app[OAuth2ProviderKeyConstant::USER]->id);
    }

    public function testExpiredTokenWithLoginForcedExceptionHandler()
    {
        $app = $this->registerProvider();
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(new LoginForcedExceptionHandler(), new TestUserProvider()));

        $access_token = TokenConstant::TOKEN_EXPIRED;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_FOUND, $resp->getStatusCode());

        $state = ($resp->headers->getCookies()[0])->getValue();
        /** @var Grant $grant */
        $grant = $app[OAuth2ProviderKeyConstant::GRANT];
        $authorize_url = $grant->authorize($state, $req->getUri());

        $this->assertEquals($authorize_url, $resp->headers->get('location'));
    }

    public function testExpiredTokenWithLoginRequiredExceptionHandler()
    {
        $app = $this->registerProvider();
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(new LoginRequiredExceptionHandler(), new TestUserProvider()));

        $access_token = TokenConstant::TOKEN_EXPIRED;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $resp->getStatusCode());
    }

    public function testInvalidPayloadToken()
    {
        $app = $this->registerProvider();
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(new LoginRequiredExceptionHandler(), new TestUserProvider()));

        $access_token = TokenConstant::TOKEN_INVALID_PAYLOAD;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $resp->getStatusCode());
    }

    public function testInvalidSignatureToken()
    {
        $app = $this->registerProvider();
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(new LoginRequiredExceptionHandler(), new TestUserProvider()));

        $access_token = TokenConstant::TOKEN_INVALID_SIGNATURE;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $resp->getStatusCode());
    }

    public function testInvalidScopeTokenWithLoginForcedExceptionHandler()
    {
        $app = $this->registerProvider();
        $app['debug'] = true;
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(new LoginForcedExceptionHandler(), new TestUserProvider(), ['test_scope']));

        $access_token = TokenConstant::TOKEN_HAS_NO_SCOPE;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_FOUND, $resp->getStatusCode());

        $state = ($resp->headers->getCookies()[0])->getValue();
        /** @var Grant $grant */
        $grant = $app[OAuth2ProviderKeyConstant::GRANT];
        $authorize_url = $grant->authorize($state, $req->getUri(), ['test_scope']);

        $this->assertEquals($authorize_url, $resp->headers->get('location'));
    }

    public function testInvalidScopeTokenWithLoginRequiredExceptionHandler()
    {
        $app = $this->registerProvider();
        $app['debug'] = true;
        $app->get('/', function () {})
            ->before($app[OAuth2ProviderKeyConstant::MIDDLEWARE]->authorize(new LoginRequiredExceptionHandler(), new TestUserProvider(), ['test_scope']));

        $access_token = TokenConstant::TOKEN_HAS_NO_SCOPE;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        $resp = $app->handle($req);

        $this->assertEquals(Response::HTTP_FORBIDDEN, $resp->getStatusCode());
    }
}
