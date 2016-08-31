<?php
namespace Poirot\OAuth2\Model;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityAuthCode;

use Poirot\Std\Struct\DataOptionsOpen;


class AuthCode 
    extends DataOptionsOpen
    implements iEntityAuthCode
{
    protected $identifier;
    protected $clientIdentifier;
    protected $expiryDateTime;
    protected $scopes = array();
    protected $ownerIdentifier;
    protected $CodeChallenge;
    protected $CodeChallengeMethod;
    protected $redirectUri;


    /**
     * Unique Token Identifier
     *
     * @return string|int
     */
    function getIdentifier()
    {
        if (!$this->identifier)
            // generate token if it not provided!
            $this->setIdentifier(\Poirot\OAuth2\generateUniqueIdentifier());
        
        return $this->identifier;
    }

    /**
     * Set Token Identifier
     * 
     * @param string|int $identifier
     * 
     * @return $this
     */
    function setIdentifier($identifier)
    {
        if ($identifier !== null && ! (is_int($identifier) || is_string($identifier)) )
            throw new \InvalidArgumentException(sprintf(
                'Identifier must be int or string; given: (%s).'
                , \Poirot\Std\flatten($identifier)
            ));
            
        $this->identifier = $identifier;
        return $this;
    }

    /**
     * Client Identifier That Token Issued To
     *
     * @return string|int
     */
    function getClientIdentifier()
    {
        return $this->clientIdentifier;
    }

    /**
     * Set Client Identifier That Token Issued To
     * 
     * @param string|int $clientIdentifier
     * 
     * @return $this
     */
    function setClientIdentifier($clientIdentifier)
    {
        if ($clientIdentifier !== null && ! (is_int($clientIdentifier) || is_string($clientIdentifier)) )
            throw new \InvalidArgumentException(sprintf(
                'Identifier must be int or string; given: (%s).'
                , \Poirot\Std\flatten($clientIdentifier)
            ));
        
        $this->clientIdentifier = $clientIdentifier;
        return $this;
    }

    /**
     * Get the token's expiry date time
     *
     * @return \DateTime
     */
    function getExpiryDateTime()
    {
        return $this->expiryDateTime;
    }

    /**
     * Set Expiry DateTime
     * 
     * @param \DateTime $expiryDateTime
     * 
     * @return $this
     */
    function setExpiryDateTime(\DateTime $expiryDateTime)
    {
        $this->expiryDateTime = $expiryDateTime;
        return $this;
    }

    /**
     * Get Issued Scopes
     * 
     * @return string[]
     */
    function getScopes()
    {
        return $this->scopes;
    }

    /**
     * Set Issued Scopes
     * 
     * @param string[] $scopes
     * 
     * @return $this
     */
    function setScopes($scopes)
    {
        if (!is_array($scopes))
            throw new \InvalidArgumentException(sprintf(
                'Scopes must be array of string contains scope identifier; given: (%s).'
                , \Poirot\Std\flatten($scopes)
            ));
        
        $this->scopes = $scopes;
        return $this;
    }

    /**
     * Add Scope To Current Scopes
     *
     * @param string $scope
     * 
     * @return $this
     */
    function setScope($scope)
    {
        $scopes = array_merge($this->getScopes(), array( (string) $scope) );
        $this->setScopes($scopes);
        return $this;
    }

    /**
     * Clear Scopes
     * 
     * @return $this
     */
    function clearScopes()
    {
        $this->scopes = array();
        return $this;
    }

    /**
     * Resource Owner Of Token
     *
     * @return string|int|null
     */
    function getOwnerIdentifier()
    {
        return $this->ownerIdentifier;
    }

    /**
     * Set Resource Owner Identifier If Has
     *
     * @param string|int $ownerIdentifier
     * 
     * @return $this
     */
    function setOwnerIdentifier($ownerIdentifier)
    {
        if ($ownerIdentifier !== null && ! (is_int($ownerIdentifier) || is_string($ownerIdentifier)) )
            throw new \InvalidArgumentException(sprintf(
                'Identifier must be int or string; given: (%s).'
                , \Poirot\Std\flatten($ownerIdentifier)
            ));
        
        $this->ownerIdentifier = $ownerIdentifier;
        return $this;
    }

    /**
     * Redirect Uri That Auth Code Generated For
     *
     * @return string
     */
    function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * @param string $redirectUri
     * @return $this
     */
    function setRedirectUri($redirectUri)
    {
        $this->redirectUri = $redirectUri;
        return $this;
    }

    /**
     * @return string
     */
    function getCodeChallenge()
    {
        return $this->CodeChallenge;
    }

    /**
     * @param string $CodeChallenge
     * @return $this
     */
    function setCodeChallenge($CodeChallenge)
    {
        $this->CodeChallenge = (string) $CodeChallenge;
        return $this;
    }

    /**
     * @return string
     */
    function getCodeChallengeMethod()
    {
        return $this->CodeChallengeMethod;
    }

    /**
     * @param string $CodeChallengeMethod
     * @return $this
     */
    function setCodeChallengeMethod($CodeChallengeMethod)
    {
        $this->CodeChallengeMethod = (string) $CodeChallengeMethod;
        return $this;
    }

}
