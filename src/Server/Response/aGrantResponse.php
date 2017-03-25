<?php
namespace Poirot\OAuth2\Server\Response;

use Poirot\OAuth2\Interfaces\Server\iDataResponseGrant;
use Poirot\Std\ConfigurableSetter;

use Poirot\Std\Struct\DataOptionsOpen;
use Psr\Http\Message\ResponseInterface;

abstract class aGrantResponse
    extends DataOptionsOpen
    implements iDataResponseGrant
{
    /**
     * Manipulate Response To Achieve Satisfiable
     * Response With Given Options.
     *
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    abstract function toResponseWith(ResponseInterface $response);
}
