<?php
namespace Poirot\OAuth2\Server\Response;

use Poirot\Std\ConfigurableSetter;

use Psr\Http\Message\ResponseInterface;

abstract class aGrantResponse
    extends ConfigurableSetter
{
    protected $params = array();
    
    
    /**
     * Manipulate Response To Achieve Satisfiable 
     * Response With Given Options.
     * 
     * @param ResponseInterface $response
     * 
     * @return ResponseInterface
     */
    abstract function buildResponse(ResponseInterface $response);

    /**
     * @return array
     */
    function getParams()
    {
        return $this->params;
    }

    /**
     * Set Extra Params
     *
     * @param array|\Traversable $params
     *
     * @return $this
     */
    function setParams($params)
    {
        if ($params instanceof \Traversable)
            $params = \Poirot\Std\cast($params)->toArray();

        if (!is_array($params))
            throw new \InvalidArgumentException(sprintf(
                'Extra Params Must Instanceof Traversable or Array; given: (%s).'
                , \Poirot\Std\flatten($params)
            ));

        $this->params = $params;
        return $this;
    }
}
