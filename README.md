# ridibooks/oauth2

[![Build Status](https://travis-ci.org/ridi/php-oauth2.svg?branch=master)](https://travis-ci.org/ridi/php-oauth2)

## 소개
- OAuth2 클라이언트와 리소스 서버를 구축하기 위한 PHP 라이브러리입니다.
- Ridi 스타일 가이드([내부 서비스간의 SSO](https://github.com/ridi/style-guide/blob/master/API.md#%EB%82%B4%EB%B6%80-%EC%84%9C%EB%B9%84%EC%8A%A4%EA%B0%84%EC%9D%98-sso))에 따라 작성 되었습니다.

## Requirements

- `PHP 7.1` or higher
- `silex/silex v1.3.x` (optional)
- `symfony/symfony v4.x.x` (optional)
- `guzzlehttp/guzzle` (optional)

## Installation

```bash
composer require ridibooks/oauth2
```

## Usage

### `JwtTokenValidator`

```php
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;

$access_token = '...';

try {
   $validator = JwtTokenValidator::create()
      ->setExpireTerm(60 * 5 /* default */);
    
    $validator->validateToken($access_token);
} catch (AuthorizationException $e) {
	// handle exception
}
```

### `ScopeChecker`

```php
$required = ['write', 'read'];
if (ScopeChecker::every($required, $granted)) {
	// pass
}
```

### `Granter`

```php
$client_info = new ClientInfo('client_id', 'client_secret', ['scope'], 'redirect_uri');
$auth_server_info = new AuthorizationServerInfo('authorization_url', 'token_url');

$granter = new Granter($client_info, $auth_server_info);
$authorization_url = $granter->authorize();
// Redirect to `$authorization_url`
```

## Usage: with Silex Provider

`OAuth2ServiceProvider`를 Silex 애플리케이션에 등록(`register`)해 사용한다.

### Services

- **`OAuth2ProviderKeyConstant::GRANTER`**
    - `authorize(string $state, string $redirect_uri = null, array $scope = null): string`: `/authorize`를 위한 URL을 반환
- **`OAuth2ProviderKeyConstant::AUTHORIZER`**
	- `autorize(Request $request): JwtToken`: `access_token` 유효성 검사 후 `JwtToken` 객체를 반환
- **`OAuth2ProviderKeyConstant::MIDDLEWARE`**
	- `authorize(OAuth2ExceptionHandlerInterface $exception_handler = null, UserProviderInterface $user_provider = null, array $required_scopes = [])`: 미들웨어를 반환
	
#### Example: `OAuth2ProviderKeyConstant::MIDDLEWARE` Service

```php
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant as KeyConstant;
use Ridibooks\OAuth2\Silex\Handler\LoginRequiredExceptionHandler;
use Ridibooks\OAuth2\Silex\Provider\OAuth2ServiceProvider;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Example\UserProvder;

// `OAuth2ServiceProvider` 등록
$app->register(new OAuth2ServiceProvider(), [
	KeyConstant::CLIENT_ID => 'example-client-id',
	KeyConstant::CLIENT_SECRET => 'example-client-secret',
	KeyConstant::JWT_VALIDATOR => JwtTokenValidator::create()->...
]);

// 미들웨어 등록
$app->get('/auth-required', [$this, 'authRequiredApi'])
	->before($app[KeyConstant::MIDDLEWARE]->authorize(new LoginRequiredExceptionHandler(), new UserProvider());
	
public function authRequiredApi(Application $app)
{
	// 사용자 추출
	$user = $app[KeyConstant::USER];
	...
}
```

#### Example: `OAuth2ProviderKeyConstant::AUTHORIZER` Service

```php
use Ridibooks\OAuth2\Authorization\Authorizer;
use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Silex\Constant\OAuth2ProviderKeyConstant;
use Ridibooks\OAuth2\Silex\Provider\OAuth2ServiceProvider;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;

...

// `OAuth2ServiceProvider` 등록
$app->register(new OAuth2ServiceProvider(), [
	KeyConstant::CLIENT_ID => 'example-client-id',
	KeyConstant::CLIENT_SECRET => 'example-client-secret',
	KeyConstant::JWT_VALIDATOR => JwtTokenValidator::create()->...
]);

...

$app->get('/', function (Application $app, Request $request) {
	/** @var Authorizer $authorizer */
	$authorizer = $app[OAuth2ProviderKeyConstant::AUTHORIZER];
	try {
		$token = $authorizer->authorize($request);
		return $token->getSubject();
	} catch (AuthorizationException $e) {
		// handle authorization error ...
	}
});
```

## Usage: with Symfony Bundle

### Services
- **`Granter()`**
    - `OAuth2ServiceProvider::getGranter()`
    - `Granter::authorize(string $state, string $redirect_uri = null, array $scope = null): string`: `/authorize`를 위한 URL을 반환
- **`Authorizer()`**
    - `OAuth2ServiceProvider::getAuthorizer()`
	- `Authorizer::autorize(Request $request): JwtToken`: `access_token` 유효성 검사 후 `JwtToken` 객체를 반환
- **`OAuth2Middleware`**
	- `OAuth2ServiceProvider::getMiddleware()`
	- `OAuth2ServiceProvider` 생성 시, Symfony Event Subscriber로 등록

### Example: `OAuth2Middleware` Service

#### Configuration
- 설정 예시는 `tests/Symfony`에서 살펴볼 수 있습니다.

##### 1. `OAuth2ServiceProviderBundle` 등록
```php
# example: <project_root>/config/bundles.php

return [
    ...,
    Ridibooks\OAuth2\Symfony\OAuth2ServiceProviderBundle::class => ['all' => true]
];
```

##### 2. Parameter 및 Service 설정
- '%env(VARIABLE)%'을 이용해 environment variable을 이용할 수 있습니다.
- Required
  - client_id
  - client_secret
  - authorize_url
  - token_url
  - key_url
  - user_info_url
  - token_cookie_domain
  - default_exception_handler
- optional
  - client_default_scope
  - client_default_redirect_uri
  - jwt_expire_term (int) : default `60 * 5` = 5분
  - default_user_provider

```yaml
# example: <project_root>/config/packages/o_auth2_service_provider.yml

o_auth2_service_provider:
  client_id: '%env(CLIENT_ID)%'
  client_secret: '%env(CLIENT_SECRET)%'
  authorize_url: https://account.dev.ridi.io/ridi/authorize/
  token_url: https://account.dev.ridi.io/oauth2/token/
  key_url: https://account.dev.ridi.io/oauth2/keys/public
  user_info_url: https://account.dev.ridi.io/accounts/me/
  token_cookie_domain: .ridi.io
  
  default_exception_handler: Ridibooks\OAuth2\Example\DefaultExceptionHandler
```

```yaml
# example: <project_root>/config/services.yml

services:
  Ridibooks\OAuth2\Example\ExampleController:
    class: Ridibooks\OAuth2\Example\ExampleController
    autowire: true
    autoconfigure: true
    public: false
    arguments:
      - '@oauth2_service_provider'
```

##### 3. Controller 설정
```php
namespace Ridibooks\OAuth2\Example;

use Ridibooks\OAuth2\Symfony\Annotation\OAuth2;
use Ridibooks\OAuth2\Symfony\Provider\OAuth2ServiceProvider;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class ExampleController extends Controller
{
    /** @var OAuth2ServiceProvider */
    private $oauth2_service_provider;

    /**
     * @param OAuth2ServiceProvider $oauth2_service_provider
     */
    public function __construct(OAuth2ServiceProvider $oauth2_service_provider)
    {
        $this->oauth2_service_provider = $oauth2_service_provider;
    }

    /**
     * @Route("/oauth2", methods={"GET"})
     * @OAuth2()
     *
     * @param Request $request
     * @return Response
     */
    public function normal(Request $request): Response
    {
        $user = $this->oauth2_service_provider->getMiddleware()->getUser();

        return new JsonResponse([
            'u_idx' => $user->getUidx(),
            'u_id' => $user->getUid()
        ]);
    }
}
```

#### OAuth2 Exception Handler 설정
- Exception Handler는 OAuth2 과정 중, 오류 발생 시 Exception 상황을 처리하는 역할을 담당합니다. 
- Application Controller에서 `default_exception_handler` 파라미터로 지정한 Exception Handler가 아닌 별도의 Exception Handler를 이용하려는 경우, 아래 절차를 따릅니다.
    - `Ridibooks\OAuth2\Symfony\Handler\OAuth2ExceptionHandlerInterface`를 implement한 Exception Handler를 생성합니다.
         - example: `Ridibooks\Test\OAuth2\Symfony\TestExceptionHandler`
    - Application Controller의 `@OAuth2` Annotation에서 `exception_handler` 속성을 지정합니다.
         - example: `@OAuth2(exception_handler="Ridibooks\Test\OAuth2\Symfony\TestExceptionHandler")`

#### Custom User Provider 설정
- User Provider는 인증 이후, User 정보를 가져오는 역할을 담당합니다.
- `default_user_provider` 파라미터를 지정하지 않은 경우, 기본적으로 `Ridibooks\OAuth2\Symfony\Provider\DefaultUserProvider`를 이용합니다.
- Application Controller에서 `default_user_provider` 파라미터로 지정한 User Provider가 아닌 별도의 User Provider를 이용하려는 경우, 아래 절차를 따릅니다.
    - `Ridibooks\OAuth2\Symfony\Provider\UserProviderInterface`를 implement한 User Provider를 생성합니다.
    - Application Controller의 `@OAuth2` Annotation에서 `user_provider` 속성을 지정합니다.
```php
namespace Ridibooks\OAuth2\Example;

use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Symfony\Provider\OAuth2ServiceProvider;
use Ridibooks\OAuth2\Symfony\Provider\UserProviderInterface;
use Symfony\Component\HttpFoundation\Request;

class CustomUserProvider implement UserProviderInterface
{
    /**
     * @param JwtToken $token
     * @param Request $request
     * @param OAuth2ServiceProvider $oauth2_service_provider
     * @return User
     */
    public function getUser(JwtToken $token, Request $request, OAuth2ServiceProvider $oauth2_service_provider): User
    {
        ...
    }
}
```

```php
namespace Ridibooks\OAuth2\Example;

use Ridibooks\OAuth2\Symfony\Annotation\OAuth2;
use Ridibooks\OAuth2\Symfony\Provider\OAuth2ServiceProvider;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class ExampleController extends Controller
{
    /**
     * @Route("/oauth2", methods={"GET"})
     * @OAuth2(user_provider="Ridibooks\OAuth2\Example\CustomUserProvider")
     *
     * @param Request $request
     * @return Response
     */
    public function normal(Request $request): Response
    {
        ...
    }
}
```
