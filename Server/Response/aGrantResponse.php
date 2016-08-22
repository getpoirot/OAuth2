<?php
namespace Poirot\OAuth2\Server\Response;

use Poirot\Std\ConfigurableSetter;

use Psr\Http\Message\ResponseInterface;

abstract class aGrantResponse
    extends ConfigurableSetter
{
    /**
     * Manipulate Response To Achieve Satisfiable 
     * Response With Given Options.
     * 
     * @param ResponseInterface $response
     * 
     * @return ResponseInterface
     */
    abstract function buildResponse(ResponseInterface $response); 
}
