<?php declare(strict_types=1);

namespace Ridibooks\OAuth2\Authorization\Key;

use GuzzleHttp\Client;
use Ridibooks\OAuth2\Authorization\Exception\AccountServerException;
use Ridibooks\OAuth2\Authorization\Exception\ClientRequestException;

class KeyRequestor
{
    public static function requestPublicKey(
        string $client_id
    ): array
    {
        $client = new Client();
        $response = $client->request('GET',
            'https://account.dev.ridi.io/oauth2/keys/public', [
                'query' => ['client_id' => $client_id]
            ]);

        return self::processResponse($response);
    }

    public static function processResponse(
        Response $response
    )
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
