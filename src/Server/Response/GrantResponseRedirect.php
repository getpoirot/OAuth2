<?php
namespace Poirot\OAuth2\Server\Response;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;

use Psr\Http\Message\ResponseInterface;

class GrantResponseRedirect
    extends aGrantResponseAccessToken
{
    protected $redirectUri;

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
            if (!$AccessToken instanceof iEntityAccessToken)
                throw new \Exception('Access Token Not Issued Into Response.');

            $currDateTime   = new \DateTime();
            $currDateTime   = $currDateTime->getTimestamp();
            $expireDateTime = $AccessToken->getDateTimeExpiration()->getTimestamp();
            
            $tokenParams = array(
                'token_type'   => 'Bearer',
                'expires_in'   => $expireDateTime - $currDateTime,
                'access_token' => (string) $AccessToken->getIdentifier(),
            );

            $responseParams = array_merge($responseParams, $tokenParams);
        }

        unset($responseParams['redirect_uri']);
        
        $redirect = \Poirot\OAuth2\buildUriQueryParams($this->redirectUri, $responseParams, '#');
        $response = $response->withStatus(302)->withHeader('Location', $redirect);
        return $response;
    }


    // Options:

    /**
     * Get Redirect Uri
     *
     * @return string
     */
    function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * Set Redirect Uri
     *
     * @param string $redirectUri
     *
     * @return $this
     */
    function setRedirectUri($redirectUri)
    {
        $this->redirectUri = (string) $redirectUri;
        return $this;
    }
}
