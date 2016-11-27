<?php
namespace Poirot\OAuth2
{
    use Psr\Http\Message\ServerRequestInterface;

    /**
     * Check Expiration Of DateTime
     *
     * @param \DateTime $dateTime
     *
     * @return boolean
     */
    function checkExpiry(\DateTime $dateTime)
    {
        $currDateTime   = new \DateTime();
        $currDateTime   = $currDateTime->getTimestamp();

        $expireDateTime = $dateTime->getTimestamp();

        return ($currDateTime-$expireDateTime > 0);
    }
    
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
                list($clientId, $clientSecret) = parseBasicAuthorizationHeader($authHeader);
            } catch (\Exception $e) { }
        }

        // maybe client_id find in request query params
        // used in authorization grants ...
        $reqParams = $request->getQueryParams();
        if ($QclientId = \Poirot\Std\emptyCoalesce(@$reqParams['client_id']) ) {
            $clientId  = $QclientId;
            $clientSecret = null;
        } else {
            $reqParams    = (array) $request->getParsedBody();
            $clientId     = \Poirot\Std\emptyCoalesce(@$reqParams['client_id'], $clientId);
            $clientSecret = \Poirot\Std\emptyCoalesce(@$reqParams['client_secret'], $clientSecret);
        }

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
        foreach($params as $param => $value) {
            $value = urlencode($value);
            $paramsJoined[] = "$param=$value";
        }
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
     * @throws \Exception
     */
    function generateUniqueIdentifier($length = 40)
    {
        try {
            return bin2hex(random_bytes($length));
        } catch (\TypeError $e) {
            throw new \Exception('Server Error While Creating Unique Identifier.');
        } catch (\Error $e) {
            throw new \Exception('Server Error While Creating Unique Identifier.');
        } catch (\Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            throw new \Exception('Server Error While Creating Unique Identifier.');
        }
    }


    /**
     * Parse Basic Authorization Header Value To It's
     * Credential Values
     *
     * Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
     *
     * @param string $headerValue
     *
     * @return array [username=>'', 'password'=>'']
     * @throws \Exception Invalid Header
     */
    function parseBasicAuthorizationHeader($headerValue)
    {
        // Decode the Authorization header
        $auth = substr($headerValue, strlen('Basic '));
        $auth = base64_decode($auth);
        if (!$auth)
            throw new \RuntimeException('Unable to base64_decode Authorization header value');

        if (!ctype_print($auth))
            throw new \Exception('Invalid or Empty Authorization Credential.');

        $creds = array_filter(explode(':', $auth));
        if (count($creds) != 2)
            throw new \Exception('Invalid Authorization Credential; Missing username or password.');

        $credential = array('username' => $creds[0], 'password' => $creds[1], 0=>$creds[0], 1=>$creds[1]);
        return $credential;
    }
}
