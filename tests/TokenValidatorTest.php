<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2Resource;

use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Validator\JwtInfo;
use Ridibooks\OAuth2\Authorization\Validator\JwtTokenValidator;


final class TokenValidatorTest extends TestCase
{
    private $secret = 'secret';

    private function introspect($access_token)
    {
        $jwt_info = new JwtInfo($this->secret, new HS256());
        $validator = new JwtTokenValidator($jwt_info);

        return $validator->validateToken($access_token);
    }

    public function testCanIntrospect()
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.Eh_kyD7VS5hbveUfWryK_uST2wMpWeESnCrfoJvLCbQ';
        $token = $this->introspect($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testIntrospectExpiredToken()
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE1MjExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.0IkMVrnHc6Z6HznxjURS3vvKd-4aF58pbmqgP8rTyYs';
        $token = $this->introspect($access_token);

        $this->assertNotNull($token);
        $this->assertInstanceOf(JwtToken::class, $token);
        $this->assertTrue($token->isExpired());
    }

    public function testCannotIntrospectWrongFormatToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIyIjoicmlkaW9hdXRoMnRlc3QiLCJ1X2lkeCI6MjgwMzA1MCwiZXhwIjoxOTMxMTAzNDg1LCJjbGllbnRfaWQiOiJpYXg3T2NDdVlKOFN1NXA5c3dqczdSTm9zTDd6WVo0emRWNXh5SFZ4Iiwic2NvcGUiOiJhbGwifQ.zqq8a_T2eViu8kNZ0jBuPITx-hnVt9NsTj-nwdWUhR4';
        $this->introspect($access_token);
    }

    public function testCannotIntrospectInvalidSignToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIyIjoicmlkaW9hdXRoMnRlc3QiLCJ1X2lkeCI6MjgwMzA1MCwiZXhwIjoxOTMxMTAzNDg1LCJjbGllbnRfaWQiOiJpYXg3T2NDdVlKOFN1NXA5c3dqczdSTm9zTDd6WVo0emRWNXh5SFZ4Iiwic2NvcGUiOiJhbGwifQ.dK7B8_kdwdq0IUyre3vwXa0swmDD_mKed-3W2Zp4HtE';
        $this->introspect($access_token);
    }

    public function testCannotIntrospectEmptyToken()
    {
        $this->expectException(InvalidJwtException::class);

        $access_token = '';
        $this->introspect($access_token);
    }
}
