<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Interfaces\Server\iGrant;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\Std\ConfigurableSetter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


class GrantAggregateGrants
    extends ConfigurableSetter
    implements iGrant
{
    /** @var iGrant[] */
    protected $attached_grants = array();

    /** @var iGrant Responder Prepared Grant */
    protected $grantResponder;


    /**
     * Respond To Grant Request
     *
     * @param ResponseInterface $response
     * 
     * @return ResponseInterface prepared response
     * @throws exOAuthServer
     */
    function respond(ResponseInterface $response)
    {
        $grant = $this->lastGrantResponder();
        if ($grant === null)
            throw exOAuthServer::unsupportedGrantType();

        return $grant->respond($response);
    }

    /**
     * Can This Grant Respond To Request
     *
     * - usually it match against "grant_type" request
     *
     * @param ServerRequestInterface $request
     *
     * @return iGrant|false Prepared grant with request
     */
    function canRespondToRequest(ServerRequestInterface $request)
    {
        foreach ($this->attached_grants as $grant) {
            if ($grant = $grant->canRespondToRequest($request)) {
                $this->grantResponder = $grant;
                return $grant;
            }
        }

        return false;
    }

    /**
     * Get Last Grant Responder
     * 
     * @return iGrant|null
     */
    function lastGrantResponder()
    {
        return $this->grantResponder;
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