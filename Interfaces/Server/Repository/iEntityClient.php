<?php
namespace Poirot\OAuth2\Interfaces\Server\Repository;

interface iEntityClient
{
    /**
     * Unique ClientID
     *
     * @return string|int
     */
    function getIdentifier();

    /**
     * Client Type Mostly Used To Restrict Client From
     * Some Authorization Grant
     *
     * @link https://tools.ietf.org/html/rfc6749#section-2.1
     *
     * @return string
     */
    function getClientType();


    /**
     * Get Client Name
     * this is informational data that showed into user
     *
     * @return string
     */
    function getName();

    /**
     * Description About Client
     * this is informational data that showed into user
     *
     * @return string|null
     */
    function getDescription();

    /**
     * Get Http Address Of Client Logo Image
     * this is informational data that showed into user
     * 
     * @return string
     */
    function getImage();


    /**
     * Client Secret Key
     *
     * @return string
     */
    function getSecretKey();

    /**
     * Owner Of Client
     * this the user that register client in panel
     *
     * @return string|int|null
     */
    function getOwnerIdentifier();

    /**
     * Default Client Scopes
     *
     * !! the grant request scopes must equal or less from defaults
     *
     * @return string[]
     */
    function getScope();

    /**
     * Returns the registered redirect URI
     *
     * @return string[]
     */
    function getRedirectUri();

    /**
     * residents is company clients(such as server as a service) that 
     * in follow don't need display of approve page.
     * 
     * @return boolean
     */
    function isResidentClient();
}
