<?php
namespace Poirot\OAuth2\Server\Grant;

use Poirot\OAuth2\Interfaces\Server\iGrant;
use Poirot\OAuth2\Server\Exception\exOAuthServer;
use Poirot\Std\ConfigurableSetter;
use Poirot\Std\Interfaces\Pact\ipConfigurable;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


class GrantAggregateGrants
    extends ConfigurableSetter
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
     * @param array|\Traversable $options
     */
    function __construct($options = null)
    {
        $this->putBuildPriority( array('attached_grants',) );
        return parent::__construct($options);
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
            if ($grant instanceof ipConfigurable) {
                ## Override Grant Options From Config
                $options = (isset($this->atached_grants_options['default']))
                    ? $this->atached_grants_options['default']
                    : array();

                if (isset($this->atached_grants_options[$index])) {
                    $options = array_merge($options, $this->atached_grants_options[$index]);
                    unset($this->atached_grants_options[$index]);
                }

                // don't throw exception if options not match
                $grant->with($options, false);
            }

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

    /**
     * Set Options Override For Grants
     *
     * @param array $options
     *
     * @return $this
     */
    function setOptionsOverride($options)
    {
        $this->atached_grants_options = $options;
        return $this;
    }
}
