<?php
namespace Poirot\OAuth2\Server\Response;

use Psr\Http\Message\ResponseInterface;


class GrantResponse
    extends aGrantResponse
{
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

        $response = $response
            ->withStatus(200)
            ->withHeader('pragma', 'no-cache')
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json; charset=UTF-8');

        $content = json_encode($responseParams);
        $response->getBody()->write($content);
        return $response;
    }
}
