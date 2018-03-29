<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2Resource;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2Resource\Resource\Constant\Scope;
use Ridibooks\OAuth2Resource\Resource\ScopeChecker;


final class ResourceTest extends TestCase
{
    public function testCanCheckScope(): void
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = ['write'];
        $this->assertTrue(ScopeChecker::Check($require_scope, $user_scope));
    }

    public function testCanCheckDisallowScope(): void
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = ['write_comment'];
        $this->assertFalse(ScopeChecker::Check($require_scope, $user_scope));
    }

    public function testCanCheckAndScope(): void
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = ['write_profile', 'write_pay', 'write_comment'];
        $this->assertTrue(ScopeChecker::Check($require_scope, $user_scope));
    }

    public function testCanCheckDisallowAndScope(): void
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = ['write_profile'];
        $this->assertFalse(ScopeChecker::Check($require_scope, $user_scope));
    }

    public function testCanCheckAllScope(): void
    {
        $require_scope = ['write', 'read', ['write_profile', 'write_pay']];
        $user_scope = [Scope::ALL];
        $this->assertTrue(ScopeChecker::Check($require_scope, $user_scope));
    }
}
