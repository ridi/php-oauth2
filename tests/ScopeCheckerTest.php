<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2Resource;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Validator\ScopeChecker;
use Ridibooks\OAuth2\Constant\ScopeConstant;


final class ScopeCheckerTest extends TestCase
{
    public function testCanCheckScope()
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = ['write'];
        $this->assertTrue(ScopeChecker::check($require_scope, $user_scope));
    }

    public function testCanCheckDisallowScope()
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = ['write_comment'];
        $this->assertFalse(ScopeChecker::check($require_scope, $user_scope));
    }

    public function testCanCheckAndScope()
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = ['write_profile', 'write_pay', 'write_comment'];
        $this->assertTrue(ScopeChecker::check($require_scope, $user_scope));
    }

    public function testCanCheckDisallowAndScope()
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = ['write_profile'];
        $this->assertFalse(ScopeChecker::check($require_scope, $user_scope));
    }

    public function testCanCheckAllScope()
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = [ScopeConstant::SCOPE_FULL_AUTHORITY];
        $this->assertTrue(ScopeChecker::check($require_scope, $user_scope));
    }
}
