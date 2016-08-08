<?php
namespace Module\Places\Model\Repository;

use Module\MongoDriver\Model\Repository\aRepository;
use Module\Places\Interfaces\iRepoPlaces;
use Module\Places\Model\Place;
use Module\Places\Model\PlaceGeometryObject;

/**
 * Note:
 *
 * !! Geospatial queries must have indexes applied to work.
 *
 * !! If you wanted to have your application query for exp. all “Ford” affiliated dealerships
 *    available close to the co-ordinates provided, you would use compound-indexes.
 */

class Places extends aRepository
    implements iRepoPlaces
{
    /**
     * Initialize Object
     *
     */
    protected function __init()
    {
        $this->setModelPersist(new Place);
    }

    /**
     * Adds new category
     *
     * @param array|\Traversable $data DataStruct of place fields
     *
     * @return Place Inserted place contains ID
     * @throws \Exception Data fields not fulfilled
     */
    function insert($data)
    {
        if (!(is_array($data) || $data instanceof \Traversable))
            throw new \InvalidArgumentException(sprintf(
                'Invalid Data Struct Provided. given: (%s).'
                , \Poirot\Std\flatten($data)
            ));

        $place = new Place($data);
        if (!$place->isFulfilled())
            throw new \Exception('Category Options not fulfilled.');

        $r = $this->_query()->insertOne($place);
        $place->{Place::ID} = $r->getInsertedId();

        return $place;
    }

    /**
     * Gets place by given id
     *
     * @param string $placeID
     *
     * @return Place
     * @throws \Exception Not Exists
     */
    function findByID($placeID)
    {
        $r = $this->_query()->findOne([
            Place::ID  => $placeID,
        ]);

        if (!$r)
            throw new \RuntimeException(sprintf('Place with ID(%s) not found.', $placeID));

        return $r;
    }

    /**
     * Find Nearby Places
     *
     * @param float $longitude
     * @param float $latitude
     * @param null  $maxDistance Distance In Meter
     *
     * @return \Traversable[Place]
     */
    function findAllNearby($longitude, $latitude, $maxDistance = null)
    {
        $r = $this->_query()->find([
            Place::Geometry.'.'.PlaceGeometryObject::Location => [
                '$nearSphere' => [
                    '$geometry' => [
                        'type'        => 'Point',
                        'coordinates' => [$longitude, $latitude]
                    ],
                    '$maxDistance' => $maxDistance
                ]
            ],
        ]);

        return $r;
    }
    
    /**
     * Delete place
     *
     * @param Place $place The place instance
     *
     * @return int Deleted Count
     */
    function delete(Place $place)
    {
        $r = $this->_query()->deleteOne([
            Place::ID => $place->{Place::ID}
        ]);

        return $r->getDeletedCount();
    }
}
