<?php
namespace Poirot\OAuth2\Interfaces\Server;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface iGrant
{
    /**
     * Can This Grant Respond To Request
     * 
     * - usually it match against "grant_type" request
     * 
     * @param ServerRequestInterface $request
     * 
     * @return iGrant|false Prepared grant with request
     */
    function canRespondToRequest(ServerRequestInterface $request);

    /**
     * Respond To Grant Request
     *
     * @param ResponseInterface  $response
     *
     * @return ResponseInterface prepared response
     */
    function respond(ResponseInterface $response);
}
