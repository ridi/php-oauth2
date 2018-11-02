<?php
declare(strict_types=1);

namespace Ridibooks\OAuth2\Symfony\Provider;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;

class User
{
    /** @var int */
    private $u_idx;

    /** @var string */
    private $u_id;

    /** @var string */
    private $email;

    /** @var bool */
    private $is_verified_adult;

    /**
     * @param string $user_info_json
     * @throws AuthorizationException
     */
    public function __construct(string $user_info_json)
    {
        $json = json_decode($user_info_json);
        if (is_null($json) || !isset($json->result)) {
            throw new AuthorizationException('Invalid user info json response');
        }
        $result = $json->result;

        $this->u_idx = $result->idx;
        $this->u_id = $result->id;
        $this->email = $result->email;
        $this->is_verified_adult = $result->is_verified_adult;
    }

    /**
     * @return int
     */
    public function getUidx(): int
    {
        return $this->u_idx;
    }

    /**
     * @return string
     */
    public function getUid(): string
    {
        return $this->u_id;
    }

    /**
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * @return bool
     */
    public function isVerifiedAdult(): bool
    {
        return $this->is_verified_adult;
    }
}
