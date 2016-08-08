<?php
namespace Poirot\OAuth2\Interfaces\Server;

use Poirot\OAuth2\Server\Grant\Exception\exInvalidRequest;
use Poirot\OAuth2\Server\Grant\Exception\exOAuthServer;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface iGrant
{
    /**
     * Respond To Grant Request
     * 
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * 
     * @return ResponseInterface prepared response
     * @throws exInvalidRequest|exOAuthServer
     */
    function respond(ServerRequestInterface $request, ResponseInterface $response);
    
    /**
     * Can This Grant Respond To Request
     * 
     * - usually it match against "grant_type" request
     * 
     * @param ServerRequestInterface $request
     * 
     * @return boolean
     */
    function canRespondToRequest(ServerRequestInterface $request);
}
