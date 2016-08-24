<?php
namespace Poirot\OAuth2
{
    use Poirot\OAuth2\Server\Grant\Exception\exServerError;
    
    use Poirot\AuthSystem\Authenticate\Identifier\HttpDigest;
    
    use Psr\Http\Message\ServerRequestInterface;

    /**
     * Parse and Retrieve Client ID / Secret Key From Request
     *
     * - it can be on Authorize Header as Basic Authorization
     * - it can be passed as body message form-encoded with params
     *   client_id, client_secret
     *
     * @param ServerRequestInterface $request
     *
     * @return object{clientId, secretKey}|false
     */
    function parseClientIdSecret(ServerRequestInterface $request)
    {
        $clientId     = null;
        $clientSecret = null;

        $authHeader = $request->getHeaderLine('Authorization');
        if ($authHeader) {
            try {
                list($clientId, $clientSecret) = HttpDigest\parseBasicAuthorizationHeader($authHeader);
            } catch (\Exception $e) { }
        }

        // maybe client_id find in request query params
        // used in authorization grants ...
        $reqParams = $request->getQueryParams();
        $clientId  = \Poirot\Std\emptyCoalesce(@$reqParams['client_id'], $clientId);
        
        $reqParams    = (array) $request->getParsedBody();
        $clientId     = \Poirot\Std\emptyCoalesce(@$reqParams['client_id'], $clientId);
        $clientSecret = \Poirot\Std\emptyCoalesce(@$reqParams['client_secret'], $clientSecret);

        if (isset($clientId))
            return (object) array('clientId' => $clientId, 'secretKey' => $clientSecret);
        
        return false;
    }

    /**
     * Build Uri Query Params
     * 
     * note: function must not responsible for url encoding 
     * 
     * @param string $uri
     * @param array  $params
     * @param string $queryDelimiter
     * 
     * @return string
     */
    function buildUriQueryParams($uri, $params = array(), $queryDelimiter = '?')
    {
        $uri .= (strstr($uri, $queryDelimiter) === false) ? $queryDelimiter : '&';

        $paramsJoined = array();
        foreach($params as $param => $value)
            $paramsJoined[] = "$param=$value";
        $query = implode('&', $paramsJoined);
        
        // url encoded data break tokens structure, then url encoding will happen outside if needed. 
        #$query = http_build_query($params);

        $uri  = $uri . $query;
        return $uri;
    }
    
    /**
     * Generate a unique identifier
     *
     * @param int $length
     *
     * @return string
     * @throws exServerError
     */
    function generateUniqueIdentifier($length = 40)
    {
        try {
            return bin2hex(random_bytes($length));
        } catch (\TypeError $e) {
            // TODO
            throw new exServerError;
        } catch (\Error $e) {
            // TODO
            throw new exServerError;
        } catch (\Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            // TODO
            throw new exServerError;
        }
    }
}
