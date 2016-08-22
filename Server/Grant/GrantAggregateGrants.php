<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Interfaces\Server\iGrant;
use Poirot\OAuth2\Server\Grant\Exception\exInvalidRequest;
use Poirot\OAuth2\Server\Grant\Exception\exOAuthServer;
use Poirot\Std\ConfigurableSetter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class GrantAggregateGrants
    extends ConfigurableSetter
    implements iGrant
{
    /** @var iGrant[] */
    protected $attached_grants = array();
    
    
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
        foreach ($this->attached_grants as $grant)
            if ($grant->canRespondToRequest($request))
                return $grant->respond($request, $response);

        throw new exInvalidRequest;
    }

    /**
     * Can This Grant Respond To Request
     *
     * - usually it match against "grant_type" request
     *
     * @param ServerRequestInterface $request
     *
     * @return boolean
     */
    function canRespondToRequest(ServerRequestInterface $request)
    {
        foreach ($this->attached_grants as $grant)
            if ($grant->canRespondToRequest($request))
                return true;
        
        return false;
    }
    
    
    // Options:

    /**
     * Set Attached Grants
     * 
     * @param \Poirot\OAuth2\Interfaces\Server\iGrant[] $attached_grants
     * 
     * @return $this
     */
    function setAttachedGrants(array $attached_grants)
    {
        foreach ($attached_grants as $grant)
            $this->attachGrant($grant);
        
        return $this;
    }

    /**
     * Attach Grant
     * 
     * @param iGrant $grant
     * 
     * @return $this
     */
    function attachGrant(iGrant $grant)
    {
        array_push($this->attached_grants, $grant);
        return $this;
    }
}