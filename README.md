# ridibooks/oauth2

[![Build Status](https://travis-ci.org/ridi/php-oauth2.svg?branch=master)](https://travis-ci.org/ridi/php-oauth2)

## 소개
- OAuth2 클라이언트와 리소스 서버를 구축하기 위한 PHP 라이브러리입니다.
- Ridi 스타일 가이드([내부 서비스간의 SSO](https://github.com/ridi/style-guide/blob/master/API.md#%EB%82%B4%EB%B6%80-%EC%84%9C%EB%B9%84%EC%8A%A4%EA%B0%84%EC%9D%98-sso))에 따라 작성 되었습니다.

## Requirements

- `PHP 7.1` or higher
- `Silex v1.2.x or v1.3.x`

## Installation

```bash
composer require ridibooks/oauth2
```

## Usage

### `JwtTokenValidator`

```php
$access_token = '...';
$validator = new JwtTokenValidator(TokenConstant::SECRET, TokenConstant::ALGORITHM, 300);
try {
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
use Example\UserProvder;

// `OAuth2ServiceProvider` 등록
$app->register(new OAuth2ServiceProvider(), [
	KeyConstant::CLIENT_ID => 'example-client-id',
	KeyConstant::CLIENT_SECRET => 'example-client-secret',
	KeyConstant::JWT_ALGORITHM => 'HS256',
	KeyConstant::JWT_SECRET => 'example-secret'
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

...

// `OAuth2ServiceProvider` 등록
$app->register(new OAuth2ServiceProvider(), [
	KeyConstant::CLIENT_ID => 'example-client-id',
	KeyConstant::CLIENT_SECRET => 'example-client-secret',
	KeyConstant::JWT_ALGORITHM => 'HS256',
	KeyConstant::JWT_SECRET => 'example-secret'
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
