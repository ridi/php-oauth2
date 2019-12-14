<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Validator;

use Ridibooks\OAuth2\Authorization\Exception\AuthorizationException;
use Ridibooks\OAuth2\Authorization\Exception\ExpiredTokenException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidJwtSignatureException;
use Ridibooks\OAuth2\Authorization\Exception\InvalidTokenException;
use Ridibooks\OAuth2\Authorization\Exception\TokenNotFoundException;
use Ridibooks\OAuth2\Authorization\Token\JwtToken;
use Ridibooks\OAuth2\Authorization\Key\KeyHandler;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWS;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Core\JWK;
use InvalidArgumentException;

class JwtTokenValidator
{
    /** @var KeyHandler */
    private $keyHandler;
    /**
     * @return JwtTokenValidator
     */
    static public function create()
    {
        return new JwtTokenValidator();
    }

    protected function __construct()
    {
        $this->keyHandler = new KeyHandler();
    }

    private function getJws(string $access_token): JWS
    {
        $serializerManager = new JWSSerializerManager([
            new CompactSerializer(),
        ]);


        try {
            return $serializerManager->unserialize($access_token);
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

    }

    private function checkAndGetHeader(JWS $jws): array
    {
        $headerCheckerManager = new HeaderCheckerManager(
            [
                new AlgorithmChecker(['RS256']), // We check the header "alg" (algorithm)
            ],
            [
                new JWSTokenSupport(), // Adds JWS token type support
            ]
        );
        try {
            $headerCheckerManager->check($jws, 0, ['alg', 'typ', 'kid']);
        } catch (MissingMandatoryHeaderParameterException $e){
            throw new InvalidJwtException($e->getMessage());
        }

        return $jws->getSignature(0)->getProtectedHeader();
    }

    private function checkAndGetClaims(JWS $jws): array
    {
        $claimCheckerManager = new ClaimCheckerManager(
            [
                new Checker\ExpirationTimeChecker(),
            ]
        );
        $claims = json_decode($jws->getPayload(), true);
        try {
            $claimCheckerManager->check($claims, ['sub', 'u_idx', 'exp', 'client_id']);
        } catch (InvalidClaimException $e) {
            throw new ExpiredTokenException($e->getMessage());
        } catch (MissingMandatoryClaimException $e) {
            throw new InvalidTokenException($e->getMessage());
        }

        return $claims;
    }

    private function verifyJwsWithJwk(JWS $jws, JWK $jwk): void
    {
        $algorithmManager = new AlgorithmManager([
            new RS256(),
        ]);
        $jwsVerifier = new JWSVerifier(
            $algorithmManager
        );

        try {
            $isVerified = $jwsVerifier->verifyWithKey($jws, $jwk, 0);
        } catch (InvalidArgumentException $e) {
            throw new InvalidJwtException($e->getMessage());
        }

        if (!$isVerified) {
            throw new InvalidJwtSignatureException();
        }
    }

    /**
     * @param $expire_term
     * @return $this
     */
    public function setExpireTerm(int $expire_term) {
        if (is_numeric($expire_term)) {
            $this->keyHandler->setExpireTerm($expire_term);
        }

        return $this;
    }

    /**
     * @param string|null $access_token
     * @return JwtToken
     * @throws AuthorizationException
     * @throws TokenNotFoundException
     */
    public function validateToken($access_token): JwtToken
    {
        if (!isset($access_token)) {
            throw new TokenNotFoundException();
        }

        $jws = $this->getJws($access_token);

        $header = $this->checkAndGetHeader($jws);
        $claims = $this->checkAndGetClaims($jws);

        $jwk = $this->keyHandler->getPublicKeyByKid($claims['client_id'], $header['kid']);
        $this->verifyJwsWithJwk($jws, $jwk);

        return JwtToken::createFrom($claims);
    }
}
