<?php
namespace Module\OAuth2Client\Services;

use Poirot\Application\aSapi;
use Poirot\Ioc\Container\Service\aServiceContainer;
use Poirot\Std\Struct\DataEntity;


class ServiceAuthorizeToken
    extends aServiceContainer
{
    const CONF_KEY = 'ServiceAuthorizeToken';

    protected $endPoint;
    protected $authHeader;


    /**
     * Create Service
     *
     * @return mixed
     */
    function newService()
    {
        $conf = $this->_attainConf();
        return $conf['service'];
    }


    // ..

    /**
     * Attain Merged Module Configuration
     * @return array
     */
    protected function _attainConf()
    {
        $sc     = $this->services();
        /** @var aSapi $sapi */
        $sapi   = $sc->get('/sapi');
        /** @var DataEntity $config */
        $config = $sapi->config();
        $config = $config->get(\Module\OAuth2Client\Module::CONF_KEY);

        $r = array();
        if (is_array($config) && isset($config[static::CONF_KEY]))
            $r = $config[static::CONF_KEY];

        return $r;
    }
}
