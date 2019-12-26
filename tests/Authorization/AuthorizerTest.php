<?php declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Authorization;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Authorizer;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Jwk\JwkHandler;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\OAuth2\Constant\AccessTokenConstant;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Ridibooks\OAuth2\Silex\Handler\LoginRequiredExceptionHandler;
use Ridibooks\OAuth2\Silex\Provider\OAuth2ServiceProvider;
use Ridibooks\Test\OAuth2\Common\TestUserProvider;
use Ridibooks\Test\OAuth2\Common\TokenConstant;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Ridibooks\Test\OAuth2\Api\MockJwkApi;

class AuthorizerTest extends TestCase
{
    protected function setUp()
    {
        MockJwkApi::setUp();
    }

    protected function tearDown()
    {
        MockJwkApi::tearDown();
    }

    private $authorization_url = 'https://account.ridibooks.com/oauth2/authorize/';
    private $token_url = 'https://account.ridibooks.com/oauth2/token/';
    private $jwk_url = 'https://account.ridibooks.com/oauth2/keys/public';

    private function registerProvider($options = [])
    {
        $app = new Application();
        $options = array_merge([
            OAuth2ProviderKeyConstant::CLIENT_ID => TokenConstant::CLIENT_ID,
            OAuth2ProviderKeyConstant::CLIENT_SECRET => TokenConstant::CLIENT_SECRET,
            OAuth2ProviderKeyConstant::AUTHORIZE_URL => $this->authorization_url,
            OAuth2ProviderKeyConstant::TOKEN_URL => $this->token_url,
            OAuth2ProviderKeyConstant::JWT_VALIDATOR => new JwtTokenValidator($this->jwk_url),
            OAuth2ProviderKeyConstant::DEFAULT_USER_PROVIDER => new TestUserProvider(),
            OAuth2ProviderKeyConstant::DEFAULT_EXCEPTION_HANDLER => new LoginRequiredExceptionHandler(),
        ], $options);
        $app->register(new OAuth2ServiceProvider(), $options);
        return $app;
    }

    public function testAuthorizerWithValidToken()
    {
        $app = $this->registerProvider();

        $app->get('/', function (Application $app, Request $request) {
            /** @var Authorizer $authorizer */
            $authorizer = $app[OAuth2ProviderKeyConstant::AUTHORIZER];
            $token = $authorizer->authorize($request);

            return $token->getSubject();
        });

        $access_token = TokenConstant::TOKEN_VALID;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        /** @var Response $response */
        $response = $app->handle($req);
        $this->assertEquals(TokenConstant::USERNAME, $response->getContent());
    }

    public function testAuthorizerWithExpiredToken()
    {
        $app = $this->registerProvider();
        $app['debug'] = true;
        $app->get('/', function (Application $app, Request $request) {
            /** @var Authorizer $authorizer */
            $authorizer = $app[OAuth2ProviderKeyConstant::AUTHORIZER];
            try {
                $token = $authorizer->authorize($request);
                return $token->getSubject();
            } catch (AuthorizationException $e) {
                $app->abort(401);
            }
        });

        $access_token = TokenConstant::TOKEN_EXPIRED;
        $req = Request::create('/', 'GET', [], [AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        /** @var Response $response */
        $response = $app->handle($req);

        $this->assertEquals(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
    }
}
