<?php

namespace Ridibooks\OAuth2Resource\Authorization\Token;

use Ridibooks\OAuth2Resource\Constant\AccessTokenConstant;

class BaseTokenInfo
{
    /**
     * @var string
     */
    protected $subject;

    /**
     * @var int
     */
    protected $expire_timestamp;

    /**
     * @var \DateTime
     */
    protected $expire_date;

    /**
     * BaseToken constructor.
     *
     * @param string $subject
     * @param int $expire_timestamp
     */
    protected function __construct(string $subject, int $expire_timestamp)
    {
        $this->subject = $subject;
        $this->expire_timestamp = $expire_timestamp;
        $this->expire_date = (new \DateTime())->setTimestamp($expire_timestamp);
    }

    /**
     * @return string
     */
    public function getSubject(): string
    {
        return $this->subject;
    }

    /**
     * @return int
     */
    public function getExpireTimestamp(): int
    {
        return $this->expire_timestamp;
    }

    /**
     * @return \DateTime
     */
    public function getExpireDate(): \DateTime
    {
        return $this->expire_date;
    }

    public function isValid(): bool
    {
        return true;
    }

    public function isExpired(int $margin = AccessTokenConstant::DEFAULT_EXPIRE_MARGIN): bool
    {
        $expired = $this->getExpireTimestamp();
        return isset($expired) ? $expired + $margin < time() : true;
    }
}
