<?php
namespace Poirot\OAuth2\Server\Grant\Exception;

class exOAuthServer 
    extends \Exception
{
    const EXCEPTION_DEFAULT_MESSAGE = 'Authentication Failed.';
    const EXCEPTION_DEFAULT_CODE    = 400;

    /**
     * exOAuthServer constructor.
     */
    final function __construct()
    {
        parent::__construct(static::EXCEPTION_DEFAULT_MESSAGE, static::EXCEPTION_DEFAULT_CODE);
    }
}
