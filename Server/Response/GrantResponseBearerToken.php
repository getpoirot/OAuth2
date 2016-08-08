<?php
namespace Poirot\OAuth2\Server\Response;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;

use Psr\Http\Message\ResponseInterface;

class GrantResponseBearerToken
    extends aGrantResponseAccessToken
{
    /**
     * Manipulate Response To Achieve Satisfiable
     * Response With Given Options.
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface Clone copy
     * @throws \Exception
     */
    function putOn(ResponseInterface $response)
    {
        $AccessToken = $this->getAccessToken();
        if (!$AccessToken instanceof iEntityAccessToken)
            throw new \Exception('Access Token Not Issued Into Response.');

        $currDateTime   = new \DateTime();
        $currDateTime   = $currDateTime->getTimestamp();
        $expireDateTime = $AccessToken->getExpiryDateTime()->getTimestamp();
        
        $responseParams = array(
            'token_type'   => 'Bearer',
            'expires_in'   => $expireDateTime - $currDateTime,
            'access_token' => $AccessToken->getIdentifier(),
        );

        # refresh token
        $RefreshToken = $this->getRefreshToken();
        if ($RefreshToken instanceof iEntityRefreshToken)
            $responseParams['refresh_token'] = $RefreshToken->getIdentifier();

        $responseParams = array_merge($this->getExtraParams(), $responseParams);

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $response->getBody()->write(json_encode($responseParams));
        return $response;
    }
}
