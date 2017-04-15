<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Interfaces\Server\iGrant;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


class GrantAggregateGrants
    implements iGrant
{
    /** @var iGrant[] */
    protected $attached_grants = array(
        // 'className' => iGrant
    );

    protected $atached_grants_options = array(
        // 'className' => $options
    );

    /** @var iGrant Responder Prepared Grant */
    protected $grantResponder;


    /**
     * Construct
     *
     * @param \Poirot\OAuth2\Interfaces\Server\iGrant[] $attachGrants
     */
    function __construct(array $attachGrants = null)
    {
        if ($attachGrants !== null)
            $this->setAttachedGrants($attachGrants);

    }


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
        foreach ($this->attached_grants as $index => $grant) {
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
        $this->attached_grants[get_class($grant)] = $grant;
        return $this;
    }
}
