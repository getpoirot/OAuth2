<?php
namespace Poirot\OAuth2\Interfaces\Server;

use Poirot\Std\Interfaces\Struct\iDataOptions;
use Psr\Http\Message\ResponseInterface;


interface iDataResponseGrant
    extends iDataOptions
{
    /**
     * Manipulate Response To Achieve Satisfiable
     * Response With Given Options.
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    function toResponseWith(ResponseInterface $response);
}
