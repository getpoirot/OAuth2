<?php
namespace Poirot\OAuth2\Server\Response\Error;

use Poirot\Std\Struct\aDataOptions;

class DataErrorResponse
    extends aDataOptions
{
    const ERR_INVALID_REQUEST        = 'invalid_request';
    const ERR_INVALID_CLIENT         = 'invalid_client';
    const ERR_INVALID_GRANT          = 'invalid_grant';
    const ERR_ACCESS_DENIED          = 'access_denied';
    const ERR_UNAUTHORIZED_CLIENT    = 'unauthorized_client';
    const ERR_UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';
    const ERR_INVALID_SCOPE          = 'invalid_scope';

    const ERR_SERVER_ERROR           = 'server_error';
    
    
    protected $error;
    protected $errorDescription;
    protected $errorUri;
    protected $hint;

    
    /**
     * @required string
     * @return mixed
     */
    function getError()
    {
        return $this->error;
    }

    /**
     * @param mixed $error
     * @return $this
     */
    function setError($error)
    {
        $this->error = $error;
        return $this;
    }

    /**
     * @return mixed
     */
    function getErrorDescription()
    {
        return $this->errorDescription;
    }

    /**
     * @param mixed $errorDescription
     * @return $this
     */
    function setErrorDescription($errorDescription)
    {
        $this->errorDescription = $errorDescription;
        return $this;
    }

    /**
     * @return mixed
     */
    function getErrorUri()
    {
        return $this->errorUri;
    }

    /**
     * @param mixed $errorUri
     * @return $this
     */
    function setErrorUri($errorUri)
    {
        $this->errorUri = $errorUri;
        return $this;
    }

    /**
     * @return mixed
     */
    function getHint()
    {
        return $this->hint;
    }

    /**
     * @param mixed $hint
     * @return $this
     */
    function setHint($hint)
    {
        $this->hint = $hint;
        return $this;
    }
}
