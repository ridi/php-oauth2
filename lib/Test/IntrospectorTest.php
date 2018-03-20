<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2Resource\RidiOAuth2;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\DataTransferObject\AccessTokenInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\DataTransferObject\JwtInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Exception\ExpireTokenException;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Helper\JwtIntrospectHelper;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\JwtIntrospector;


final class IntrospectorTest extends TestCase
{
    private $secret = 'secret';
    private $algorithm = 'HS256';

    public function testCanIntrospec(): void
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.Eh_kyD7VS5hbveUfWryK_uST2wMpWeESnCrfoJvLCbQ';

        $jwt_info = new JwtInfo($this->secret, $this->algorithm);
        $jwt_instrospector = new JwtIntrospector($jwt_info, $access_token);

        $token = $jwt_instrospector->introspect();
        $this->assertNotNull($token);
    }

    public function testCanIntrospecByHelper(): void
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.Eh_kyD7VS5hbveUfWryK_uST2wMpWeESnCrfoJvLCbQ';

        $jwt_info = new JwtInfo($this->secret, $this->algorithm);

        $access_token_info = JwtIntrospectHelper::introspect($jwt_info, $access_token);
        $this->assertInstanceOf(AccessTokenInfo::class, $access_token_info);
    }

    public function testCannotIntrospecExpiredToken(): void
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE1MjExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.0IkMVrnHc6Z6HznxjURS3vvKd-4aF58pbmqgP8rTyYs';

        $jwt_info = new JwtInfo($this->secret, $this->algorithm);

        $this->expectException(ExpireTokenException::class);
        JwtIntrospectHelper::introspect($jwt_info, $access_token);
    }

    public function testCannotIntrospecWrongFormatToken(): void
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIyIjoicmlkaW9hdXRoMnRlc3QiLCJ1X2lkeCI6MjgwMzA1MCwiZXhwIjoxOTMxMTAzNDg1LCJjbGllbnRfaWQiOiJpYXg3T2NDdVlKOFN1NXA5c3dqczdSTm9zTDd6WVo0emRWNXh5SFZ4Iiwic2NvcGUiOiJhbGwifQ.zqq8a_T2eViu8kNZ0jBuPITx-hnVt9NsTj-nwdWUhR4';

        $jwt_info = new JwtInfo($this->secret, $this->algorithm);

        $this->expectException(InvalidJwtSignatureException::class);
        JwtIntrospectHelper::introspect($jwt_info, $access_token);
    }

    public function testCannotIntrospecInvalidSignToken(): void
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIyIjoicmlkaW9hdXRoMnRlc3QiLCJ1X2lkeCI6MjgwMzA1MCwiZXhwIjoxOTMxMTAzNDg1LCJjbGllbnRfaWQiOiJpYXg3T2NDdVlKOFN1NXA5c3dqczdSTm9zTDd6WVo0emRWNXh5SFZ4Iiwic2NvcGUiOiJhbGwifQ.dK7B8_kdwdq0IUyre3vwXa0swmDD_mKed-3W2Zp4HtE';

        $jwt_info = new JwtInfo($this->secret, $this->algorithm);

        $this->expectException(InvalidJwtSignatureException::class);
        JwtIntrospectHelper::introspect($jwt_info, $access_token);
    }

    public function testCannotIntrospecEmptyToken(): void
    {
        $access_token = '';

        $jwt_info = new JwtInfo($this->secret, $this->algorithm);

        $this->expectException(InvalidJwtSignatureException::class);
        JwtIntrospectHelper::introspect($jwt_info, $access_token);
    }
}
