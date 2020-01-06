<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Api;

use GuzzleHttp\Client;
use GuzzleHttp\Psr7\Response;
use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;

class JwkApi
{
    /**
     * @param string $jwk_url
     * @param string $client_id
     * @return array
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    public static function requestPublicKey(
        string $jwk_url,
        string $client_id
    ): array
    {
        $client = new Client();
        $response = $client->request('GET', $jwk_url, [
            'query' => ['client_id' => $client_id]
        ]);

        return self::processResponse($response);
    }

    /**
     * @param Response $response
     * @return array
     * @throws AccountServerException
     * @throws ClientRequestException
     */
    public static function processResponse(
        Response $response
    ): array
    {
        if ($response->getStatusCode() >= 500) {
            throw new AccountServerException();
        } else if ($response->getStatusCode() >= 400) {
            throw new ClientRequestException();
        }

        $json_decode = json_decode($response->getBody()->getContents(), true);
        return $json_decode;
    }
}
