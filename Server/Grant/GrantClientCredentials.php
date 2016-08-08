<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Server\Grant\Exception\exInvalidRequest;
use Poirot\OAuth2\Server\Grant\Exception\exOAuthServer;
use Poirot\OAuth2\Server\Response\aGrantResponseAccessToken;
use Poirot\OAuth2\Server\Response\GrantResponseBearerToken;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

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
        $scopes = $this->assertScopes($request, $client->getScope());
        
        $accToken      = $this->issueAccessToken($client, $this->getTtlAccessToken(), null, $scopes);
        
        $grantResponse = $this->newGrantResponse();
        $grantResponse->setAccessToken($accToken);
        
        $response = $grantResponse->putOn($response);
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
