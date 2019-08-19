<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Server\Response\GrantResponseJson;

use Psr\Http\Message\ResponseInterface;

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
    const GrantType = 'client_credentials';
    
    
    /**
     * Grant identifier (client_credentials, password, ...)
     *
     * @return string
     */
    function getGrantType()
    {
        return self::GrantType;
    }

    /**
     * Respond To Grant Request
     *
     * @param ResponseInterface  $response
     *
     * @return ResponseInterface prepared response
     */
    function respond(ResponseInterface $response)
    {
        $client = $this->assertClient(true);
        list($scopeRequested, $scopes) = $this->assertScopes($client->getScope());

        $accToken      = $this->issueAccessToken($client, $this->getTtlAccessToken(), null, $scopes);
        
        $grantResponse = $this->newGrantResponse();
        $grantResponse->setAccessToken($accToken);
        if (array_diff($scopeRequested, $scopes))
            // the issued access token scope is different from the
            // one requested by the client, include the "scope"
            // response parameter to inform the client of the
            // actual scope granted.
            $grantResponse->import(array(
                'scope' => implode(' ' /* Scope Delimiter */, $scopes),
            ));

        $response = $grantResponse->toResponseWith($response);
        return $response;
    }
    
    /**
     * New Grant Response
     *
     * @return GrantResponseJson
     */
    function newGrantResponse()
    {
        return new GrantResponseJson();
    }
}
