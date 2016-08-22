<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Server\Grant\Exception\exInvalidRequest;
use Poirot\OAuth2\Server\Grant\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\aGrantResponseAccessToken;
use Poirot\OAuth2\Server\Response\GrantResponseBearerToken;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/*
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
*/

class GrantClientCredentials 
    extends aGrant
{
    /**
     * Grant identifier (client_credentials, password, ...)
     *
     * @return string
     */
    function getGrantType()
    {
        return 'client_credentials';
    }
    
    /**
     * Respond To Grant Request
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     *
     * @return ResponseInterface prepared response
     * @throws exInvalidRequest|exOAuthServer
     */
    function respond(ServerRequestInterface $request, ResponseInterface $response)
    {
        $client = $this->assertClient($request, true);
        list($scopeRequested, $scopes) = $this->assertScopes($request, $client->getScope());

        $accToken      = $this->issueAccessToken($client, $this->getTtlAccessToken(), null, $scopes);
        
        $grantResponse = $this->newGrantResponse();
        $grantResponse->setAccessToken($accToken);
        if (array_diff($scopeRequested, $scopes))
            // the issued access token scope is different from the
            // one requested by the client, include the "scope"
            // response parameter to inform the client of the
            // actual scope granted.
            $grantResponse->setExtraParams(array(
                'scope' => implode(' ' /* Scope Delimiter */, $scopes),
            ));

        $response = $grantResponse->buildResponse($response);
        return $response;
    }
    
    /**
     * New Grant Response
     *
     * @return GrantResponseBearerToken|aGrantResponseAccessToken
     */
    function newGrantResponse()
    {
        return new GrantResponseBearerToken();
    }
}
