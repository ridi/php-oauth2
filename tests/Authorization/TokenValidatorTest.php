<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Authorization;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidTokenException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Validator\JwtInfo;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\Test\OAuth2\Common\TokenConstant;

final class TokenValidatorTest extends TestCase
{
    private function validate($access_token)
    {
        $validator = new JwtTokenValidator(TokenConstant::SECRET, TokenConstant::ALGORITHM, 300);

        return $validator->validateToken($access_token);
    }

    public function testCanIntrospect()
    {
        $access_token = TokenConstant::TOKEN_VALID;
        $token = $this->validate($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testIntrospectExpiredToken()
    {
        $this->expectException(ExpiredTokenException::class);

        $access_token = TokenConstant::TOKEN_EXPIRED;
        $this->validate($access_token);
    }

    public function testCannotIntrospectWrongFormatToken()
    {
        $this->expectException(InvalidTokenException::class);

        $access_token = TokenConstant::TOKEN_INVALID_PAYLOAD;
        $this->validate($access_token);
    }

    public function testCannotIntrospectInvalidSignToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::TOKEN_INVALID_SIGNATURE;
        $this->validate($access_token);
    }

    public function testCannotIntrospectNullToken()
    {
        $this->expectException(TokenNotFoundException::class);

        $this->validate(null);
    }

    public function testCannotIntrospectEmptyToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = TokenConstant::TOKEN_EMPTY;
        $this->validate($access_token);
    }
}
