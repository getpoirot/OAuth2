<?php
namespace Poirot\OAuth2\Server\Response;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;

use Psr\Http\Message\ResponseInterface;

class GrantResponseJson
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
    function toResponseWith(ResponseInterface $response)
    {
        $responseParams = \Poirot\Std\cast($this)->toArray(function($val) {
            return $val === null;
        });
        
        if ($this->getAccessToken()) {
            $AccessToken = $this->getAccessToken();

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
        }
        
        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $content = json_encode($responseParams);
        $response->getBody()->write($content);
        return $response;
    }
}
