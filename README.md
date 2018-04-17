# ridibooks/oauth2

[![Build Status](https://travis-ci.org/ridi/php-oauth2.svg?branch=master)](https://travis-ci.org/ridi/php-oauth2)

## 소개
- OAuth2 클라이언트와 리소스 서버를 구축하기 위한 PHP 라이브러리입니다.
- Ridi 스타일 가이드([내부 서비스간의 SSO](https://github.com/ridi/style-guide/blob/master/API.md#%EB%82%B4%EB%B6%80-%EC%84%9C%EB%B9%84%EC%8A%A4%EA%B0%84%EC%9D%98-sso))에 따라 작성 되었습니다.

## 필수 조건

- `PHP 7.0` or higher
- Silex 1.3.x

## 설치

```bash
composer require ridibooks/oauth2
```

## Usage

### `Silex`와 함께 사용하기: `OAuth2ServiceProvider`

`OAuth2ServiceProvider`를 Silex 애플리케이션에 등록(`register`)해 사용한다.

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

#### 사용 가능한 옵션

- **`OAuth2ProviderKeyConstant::CLIENT_ID`**: (default = `null`)
- **`OAuth2ProviderKeyConstant::CLIENT_SECRET`**: (default = `null`)
- **`OAuth2ProviderKeyConstant::CLIENT_DEFAULT_SCOPE`**: (default = `[]`) 미들웨어에서 체크할 scope 기본값
- **`OAuth2ProviderKeyConstant::CLIENT_DEFAULT_REDIRECT_URI`**: (default = `null`)
- **`OAuth2ProviderKeyConstant::AUTHORIZE_URL`**: (default = `https://account.ridibooks.com/oauth2/authorize`)
- **`OAuth2ProviderKeyConstant::TOKEN_URL`**: (default = `https://account.ridibooks.com/oauth2/token`)
- **`OAuth2ProviderKeyConstant::JWT_ALGORITHM`**: (default = `HS256`)
- **`OAuth2ProviderKeyConstant::JWT_SECRET`**: (default = `secret`)
- **`OAuth2ProviderKeyConstant::JWT_EXPIRE_TERM`**: (default = `60 * 5` seconds)
- **`OAuth2ProviderKeyConstant::DEFAULT_EXCEPTION_HANDLER`**: (default = `null`) 미들웨어에서 사용할 기본 `OAuth2ExceptionHandlerInterface` 구현체
- **`OAuth2ProviderKeyConstant::DEFAULT_USER_PROVIDER`**: (default = `null`) 미들웨어에서 사용할 기본 `UserProviderInterface` 구현체

#### 서비스

- **`OAuth2ProviderKeyConstant::GRANT`**
    - `authorize(string $state, string $redirect_uri = null, array $scope = null): string`: `/authorize`를 위한 URL을 반환
- **`OAuth2ProviderKeyConstant::TOKEN_VALIDATOR`**
	- `validateToken(string $access_token): JwtToken`: `access_token` 유효성 검사 후 `JwtToken` 객체를 반환
- **`OAuth2ProviderKeyConstant::MIDDLEWARE`**
	- `authorize(OAuth2ExceptionHandlerInterface $exception_handler = null, UserProviderInterface $user_provider = null, array $required_scopes = [])`: 미들웨어를 반환

#### `OAuth2ExceptionHandlerInterface` 구현체

- **`IgnoreExceptionHandler`**: 인증 관련 오류를 무시
- **`LoginRequiredExceptionHandler`**: 인증 오류시 `401 UNAUTHORIZED`, `403 FORBIDDEN` 에러 발생 
- **`LoginForcedExceptionHandler`**: 인증 오류시 `OAuth2ProviderKeyConstant::AUTHORIZE_URL`로 redirect
