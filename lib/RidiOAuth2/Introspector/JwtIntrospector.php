<?php
namespace Ridibooks\OAuth2Resource\RidiOAuth2\Introspector;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use InvalidArgumentException;
use Ridibooks\OAuth2Resource\RidiOAuth2\Common\Constant\TokenType;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\DataTransferObject\JwtInfo;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Exception\ExpireTokenException;
use Ridibooks\OAuth2Resource\RidiOAuth2\Introspector\Exception\InvalidJwtSignatureException;
use stdClass;
use UnexpectedValueException;

class JwtIntrospector extends BaseIntrospector
{
    const DEFAULT_SCOPE_DELIMITER = ' ';

    private $jwt_info;

    /**
     * @param JwtInfo $jwt_info
     * @param string $access_token
     */
    public function __construct(JwtInfo $jwt_info, string $access_token)
    {
        parent::__construct($access_token, TokenType::BEARER);
        $this->jwt_info = $jwt_info;
    }

    /**
     * @return stdClass
     * @throws InvalidJwtSignatureException
     * @throws ExpireTokenException
     */
    public function introspect(): stdClass
    {
        JWT::$leeway = $this->jwt_info->getExpireTerm();

        try {
            $payload = JWT::decode($this->access_token, $this->jwt_info->getSecret(), [$this->jwt_info->getAlgorithm()]);
        } catch (BeforeValidException $e) {
            throw new ExpireTokenException();
        } catch (ExpiredException $e) {
            throw new ExpireTokenException();
        } catch (SignatureInvalidException $e) {
            throw new InvalidJwtSignatureException();
        } catch (UnexpectedValueException $e) {
            throw new InvalidJwtSignatureException();
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtSignatureException();
        }

        $payload = $this->activeResponse($payload);
        $payload = $this->splitScope($payload);

        return $payload;
    }

    /**
     * @param stdClass $payload
     * @return stdClass
     */
    private function activeResponse(stdClass $payload): stdClass
    {
        $payload->active = true;
        return $payload;
    }

    /**
     * @param stdClass $payload
     * @return stdClass
     */
    private function splitScope(stdClass $payload): stdClass
    {
        if (is_array($payload->scope)) {
            return $payload;
        }

        $payload->scope = explode(JwtIntrospector::DEFAULT_SCOPE_DELIMITER, $payload->scope);
        return $payload;
    }
}
