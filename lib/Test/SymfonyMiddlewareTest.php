<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2Resource\RidiOAuth2;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\DataTransferObject\AccessTokenInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\DataTransferObject\JwtInfo;
use Ridibooks\OAuth2Resource\RidiSymfonyOAuth2Resource\MiddlewareFactory;
use Ridibooks\OAuth2Resource\RidiSymfonyOAuth2Resource\ResourceConstants;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\HttpException;


final class SymfonyMiddlewareTest extends TestCase
{
    private $secret = 'secret';
    private $algorithm = 'HS256';

    public function testCanIntrospect(): void
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.Eh_kyD7VS5hbveUfWryK_uST2wMpWeESnCrfoJvLCbQ';

        $jwt_info = new JwtInfo($this->secret, $this->algorithm);

        $request = new Request();
        $request->cookies->add([ResourceConstants::ACCESS_TOKEN_KEY => $access_token]);

        $introspect_func = MiddlewareFactory::introspect($jwt_info);
        $introspect_func($request);

        $access_token_info = $request->attributes->get(ResourceConstants::ACCESS_TOKEN_INFO_KEY);
        $this->assertInstanceOf(AccessTokenInfo::class, $access_token_info);
    }

    public function testCannotIntrospectWhenTokenDoesNotExist(): void
    {
        $jwt_info = new JwtInfo($this->secret, $this->algorithm);
        $request = new Request();

        $this->expectException(HttpException::class);

        $introspect_func = MiddlewareFactory::introspect($jwt_info, true);
        $introspect_func($request);
    }

    public function testCanPassIntrospectWhenTokenDoesNotExist(): void
    {
        $jwt_info = new JwtInfo($this->secret, $this->algorithm);
        $request = new Request();

        $introspect_func = MiddlewareFactory::introspect($jwt_info);
        $result = $introspect_func($request);

        $this->assertNull($result);
    }

    public function testCannotPassCheckScopeWhenTokenDoesNotExist(): void
    {
        $request = new Request();

        $this->expectException(HttpException::class);

        $check_scope_func = MiddlewareFactory::checkScope(['write', 'read', ['write_profile', 'write_pay']]);
        $check_scope_func($request);
    }

    public function testCanPassCheckScope(): void
    {
        // all scope token
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.Eh_kyD7VS5hbveUfWryK_uST2wMpWeESnCrfoJvLCbQ';

        $jwt_info = new JwtInfo($this->secret, $this->algorithm);

        $request = new Request();
        $request->cookies->add([ResourceConstants::ACCESS_TOKEN_KEY => $access_token]);

        $introspect_func = MiddlewareFactory::introspect($jwt_info);
        $introspect_func($request);

        $check_scope_func = MiddlewareFactory::checkScope(['write', 'read', ['write_profile', 'write_pay']]);
        $result = $check_scope_func($request);
        $this->assertNull($result);
    }

    public function testCannotPassCheckScopeWhenWrongScope(): void
    {
        // read_home scope token
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6InJlYWRfaG9tZSJ9.-qIdxdq_1GXEJ8zOPL3P67y-UrSE2VMnN8DuyIP2GYo';

        $jwt_info = new JwtInfo($this->secret, $this->algorithm);

        $request = new Request();
        $request->cookies->add([ResourceConstants::ACCESS_TOKEN_KEY => $access_token]);

        $introspect_func = MiddlewareFactory::introspect($jwt_info);
        $introspect_func($request);

        $this->expectException(HttpException::class);

        $check_scope_func = MiddlewareFactory::checkScope(['write', 'read', ['write_profile', 'write_pay']]);
        $check_scope_func($request);
    }
}
