<?php
namespace Poirot\OAuth2\Model\Repo\Stateless;

use Poirot\OAuth2\Interfaces\Server\Repository\iEntityRefreshToken;
use Poirot\OAuth2\Model\RefreshToken as BaseRefreshToken;


class RefreshToken extends BaseRefreshToken
    implements iEntityRefreshToken
    , \Serializable
{
    /**
     * String representation of object
     * @link http://php.net/manual/en/serializable.serialize.php
     * @return string the string representation of the object or null
     * @since 5.1.0
     */
    function serialize()
    {
        $props = \Poirot\Std\cast($this)->toArray();
        return json_encode($props);
    }

    /**
     * Constructs the object
     * @link http://php.net/manual/en/serializable.unserialize.php
     * @param string $serialized <p>
     * The string representation of the object.
     * </p>
     * @return void
     * @since 5.1.0
     */
    function unserialize($serialized)
    {
        /*
         * (
         *   [identifier] => xxxxxx
         *   [client_identifier] => xxxx
         *   [expiry_date_time] => stdClass Object (
         *        [date] => 2016-11-29 08:55:51.000000
         *        [timezone_type] => 3
         *        [timezone] => UTC
         *   )
         *   [scopes] => Array (
         *      [0] => general
         *   )
         *   [owner_identifier] =>
         * )
         */
        $props = json_decode($serialized);

        $exprDateTime = new \DateTime(
            $props->expiry_date_time->date
            , new \DateTimeZone($props->expiry_date_time->timezone)
        );

        $this
            ->setIdentifier($props->identifier)
            ->setClientIdentifier($props->client_identifier)
            ->setExpiryDateTime($exprDateTime)
            ->setScopes($props->scopes)
            ->setOwnerIdentifier($props->owner_identifier)
            ->setAccessTokenIdentifier($props->access_token_identifier)
        ;
    }
}
