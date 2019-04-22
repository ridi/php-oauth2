<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Authorization;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtsignatureException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidTokenException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;
use Ridibooks\Test\OAuth2\Common\TokenConstant;

final class TokenValidatorTest extends TestCase
{
    private function validate($access_token)
    {
        return JwtTokenValidator::create()
            ->addKey(TokenConstant::SECRET, 'HS256')
            ->setExpireTerm(300)
            ->validateToken($access_token);
    }

    private function validateWithKid($access_token)
    {
        return JwtTokenValidator::create()
            ->addKey(TokenConstant::SECRET, 'HS256', 'kid0')
            ->addKeyFromFile(TokenConstant::KEY_FILE, 'RS256', 'kid1')
            ->setExpireTerm(300)
            ->validateToken($access_token);
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

    public function testCanIntrospectWithKid()
    {
        $access_token = TokenConstant::KID_TOKEN_VALID;
        $token= $this->validateWithKid($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testCannotIntrospectEmptyKid()
    {
        $this->expectException(InvalidJwtException::class);
        $access_token = TokenConstant::KID_TOKEN_WITHOUT_KID;
        $this->validateWithKid($access_token);
    }

    public function testCannotIntrospectWithInvalidKid()
    {
        $this->expectException(InvalidJwtException::class);
        $access_token = TokenConstant::KID_TOKEN_INVALID_KID;
        $this->validateWithKid($access_token);
    }
}
