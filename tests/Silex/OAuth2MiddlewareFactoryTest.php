<?php declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Silex;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
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
use Mockery;

class OAuth2MiddlewareFactoryTest extends TestCase
{
    protected function setUp()
    {
        $mock_data = <<<EOT
        {"keys":[
        {"kid": "RS999", "alg": "RS256", "kty": "RSA", "use": "sig", "n": "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==", "e": "AQAB"},
        {"kid": "kid1", "alg": "RS256", "kty": "RSA", "use": "sig", "n": "1rL5PCEv2PaAASaGldzfnlo0MiMCglC-eFxYHgUfa6a7qJhjo0QX8LeAelBlQpMCAMVGX33jUJ2FCCP_QDk3NIu74AgP7F3Z7IdmVvOfkt2myF1n3ZDyCHKdyi7MnOBtHIQCqQRGZ4XH2Ss5bmg_FuplBFT82e14UVmZx4kP-HwDjaSpvYHoTr3b5j20Ebx7aIy_SVrWeY0wxeAdFf-EOuEBQ-QIIe5Npd49gzq4CGHeNJlPQjs0EjMZFtPutCrIRSoEaLwccKQEIHcMSbsBLCJIJ5OuTmtK2WaSh7VYCrJsCbPh5tYKF6akN7TSOtDwGQVKwJjjOsxkPdYXNoAnIQ==", "e": "AQAB"}
        ]}
EOT;
        Mockery::mock('alias:Ridibooks\OAuth2\Authorization\Key\KeyRequestor', [
            "requestPublicKey" => json_decode($mock_data, true),
        ]);
    }

    protected function tearDown()
    {
        Mockery::close();
    }

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
            OAuth2ProviderKeyConstant::JWT_VALIDATOR => JwtTokenValidator::create(),
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
