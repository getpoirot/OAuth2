<?php
namespace Poirot\OAuth2\Server\Response;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAccessToken;
use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;

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
    function putOn(ResponseInterface $response)
    {
        $responseParams = array();
        
        if ($this->getAccessToken()) {
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
        }
        
        $responseParams = array_merge($this->getExtraParams(), $responseParams);

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
