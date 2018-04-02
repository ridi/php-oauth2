<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2Resource;

use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2Resource\Authorization\Token\JwtToken;
use Ridibooks\OAuth2Resource\Authorization\Validator\JwtInfo;
use Ridibooks\OAuth2Resource\Constant\AccessTokenConstant;
use Ridibooks\OAuth2Resource\Symfony\Exception\AccessTokenDoesNotExistException;
use Ridibooks\OAuth2Resource\Symfony\Exception\InsufficientScopeException;
use Ridibooks\OAuth2Resource\Symfony\Middleware\OAuth2MiddlewareFactory;
use Symfony\Component\HttpFoundation\Request;


final class SymfonyMiddlewareTest extends TestCase
{
    private $secret = 'secret';

    private function introspect($access_token = null, $request = null)
    {
        if (!isset($request)) {
            $request = new Request();
        }
        if (isset($access_token)) {
            $request->cookies->add([AccessTokenConstant::ACCESS_TOKEN_COOKIE_KEY => $access_token]);
        }

        $introspect_func = OAuth2MiddlewareFactory::introspect(new JwtInfo($this->secret, new HS256()));
        $introspect_func($request);

        $token = $request->attributes->get(AccessTokenConstant::ACCESS_TOKEN_INFO_KEY);
        return $token;
    }

    public function testCanIntrospect()
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.Eh_kyD7VS5hbveUfWryK_uST2wMpWeESnCrfoJvLCbQ';
        $token = $this->introspect($access_token);

        $this->assertInstanceOf(JwtToken::class, $token);
    }

    public function testIntrospectWhenTokenDoesNotExist()
    {
        $token = $this->introspect();
        $this->assertNull($token);
    }

    public function testCannotPassCheckScopeWhenTokenDoesNotExist()
    {
        $request = new Request();

        $this->expectException(AccessTokenDoesNotExistException::class);

        $check_scope_func = OAuth2MiddlewareFactory::checkScope(['write', 'read', ['write_profile', 'write_pay']]);
        $check_scope_func($request);
    }

    public function testCanPassCheckScope()
    {
        // all scope token
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.Eh_kyD7VS5hbveUfWryK_uST2wMpWeESnCrfoJvLCbQ';
        $request = new Request();
        $this->introspect($access_token, $request);

        $check_scope_func = OAuth2MiddlewareFactory::checkScope(['write', 'read', ['write_profile', 'write_pay']]);
        $result = $check_scope_func($request);
        $this->assertNull($result);
    }

    public function testCannotPassCheckScopeWhenWrongScope()
    {
        // read_home scope token
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6InJlYWRfaG9tZSJ9.-qIdxdq_1GXEJ8zOPL3P67y-UrSE2VMnN8DuyIP2GYo';

        $request = new Request();
        $this->introspect($access_token, $request);

        $this->expectException(InsufficientScopeException::class);

        $check_scope_func = OAuth2MiddlewareFactory::checkScope(['write', 'read', ['write_profile', 'write_pay']]);
        $check_scope_func($request);
    }

    public function testLoginRequired()
    {
        $access_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyaWRpb2F1dGgydGVzdCIsInVfaWR4IjoyODAzMDUwLCJleHAiOjE5MzExMDM0ODUsImNsaWVudF9pZCI6ImlheDdPY0N1WUo4U3U1cDlzd2pzN1JOb3NMN3pZWjR6ZFY1eHlIVngiLCJzY29wZSI6ImFsbCJ9.Eh_kyD7VS5hbveUfWryK_uST2wMpWeESnCrfoJvLCbQ';
        $request = new Request();
        $this->introspect($access_token, $request);

        $login_required_func = OAuth2MiddlewareFactory::loginRequired();
        $login_required_func($request);

        $this->assertTrue(true);
    }

    public function testCannotPassLoginRequired()
    {
        $request = new Request();

        $this->expectException(AccessTokenDoesNotExistException::class);

        $login_required_func = OAuth2MiddlewareFactory::loginRequired();
        $login_required_func($request);
    }
}
