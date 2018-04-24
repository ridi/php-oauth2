<?php
declare(strict_types=1);

namespace Ridibooks\Test\OAuth2\Authorization;

use PHPUnit\Framework\TestCase;
use Ridibooks\OAuth2\Authorization\Validator\ScopeChecker;
use Ridibooks\OAuth2\Constant\ScopeConstant;

final class ScopeCheckerTest extends TestCase
{
    public function testFullAuthorityGrantedScope()
    {
        $required = ['write', 'read'];
        $granted = [ScopeConstant::SCOPE_FULL_AUTHORITY];
        $this->assertTrue(ScopeChecker::every($required, $granted));
    }

    public function testSameRequiredAndGrantedScope()
    {
        $required = ['write', 'read', 'write_profile', 'write_pay'];
        $granted = ['write', 'read', 'write_profile', 'write_pay'];
        $this->assertTrue(ScopeChecker::every($required, $granted));
    }

    public function testNoRequiredScope()
    {
        $required = [];
        $granted = ['write'];
        $this->assertTrue(ScopeChecker::every($required, $granted));
        $required = [];
        $granted = [];
        $this->assertTrue(ScopeChecker::every($required, $granted));
    }

    public function testIncludedAllRequiredScope()
    {
        $required = ['write', 'read'];
        $granted = ['write', 'read', 'write_profile', 'write_pay'];
        $this->assertTrue(ScopeChecker::every($required, $granted));
    }

    public function testNotGrantedSomeRequiredScope()
    {
        $required = ['write', 'read'];
        $granted = ['write'];
        $this->assertFalse(ScopeChecker::every($required, $granted));
    }

    public function testNoGrantedScope()
    {
        $required = ['write', 'read'];
        $granted = [];
        $this->assertFalse(ScopeChecker::every($required, $granted));
    }
}
