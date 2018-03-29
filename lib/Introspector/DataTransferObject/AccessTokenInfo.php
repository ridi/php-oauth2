<?php

namespace Ridibooks\OAuth2Resource\Introspector\DataTransferObject;

use DateTime;
use InvalidArgumentException;
use TypeError;

class AccessTokenInfo
{
    /**
     * @var string
     */
    private $subject;

    /**
     * @var int
     */
    private $u_idx;

    /**
     * @var int
     */
    private $expire_timestamp;

    /**
     * @var datetime
     */
    private $expire_date;

    /**
     * @var string
     */
    private $client_id;

    /**
     * @var array
     */
    private $scope;

    /**
     * AccessTokenInfo constructor.
     * @param string $subject
     * @param int $u_idx
     * @param int $expire_timestamp
     * @param string $client_id
     * @param array $scope
     */
    public function __construct(string $subject, int $u_idx, int $expire_timestamp, string $client_id, array $scope)
    {
        $this->subject = $subject;
        $this->u_idx = $u_idx;
        $this->expire_timestamp = $expire_timestamp;
        $this->expire_date = (new DateTime())->setTimestamp($expire_timestamp);
        $this->client_id = $client_id;
        $this->scope = $scope;
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
    public function getUIdx(): int
    {
        return $this->u_idx;
    }

    /**
     * @return int
     */
    public function getExpireTimestamp(): int
    {
        return $this->expire_timestamp;
    }

    /**
     * @return DateTime
     */
    public function getExpireDate(): DateTime
    {
        return $this->expire_date;
    }

    /**
     * @return string
     */
    public function getClientId(): string
    {
        return $this->client_id;
    }

    /**
     * @return array
     */
    public function getScope(): array
    {
        return $this->scope;
    }

    /**
     * @param \stdClass $object
     * @return AccessTokenInfo
     */
    public static function fromObject(\stdClass $object): AccessTokenInfo
    {
        if (
            !isset($object->sub)
            || !isset($object->u_idx)
            || !isset($object->exp)
            || !isset($object->client_id)
            || !isset($object->scope)
        ) {
            throw new InvalidArgumentException();
        }

        try {
            return new AccessTokenInfo($object->sub, $object->u_idx, $object->exp, $object->client_id, $object->scope);
        } catch (TypeError $e) {
            throw new InvalidArgumentException();
        }
    }
}
