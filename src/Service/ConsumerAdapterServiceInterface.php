<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_magic_link\Service;

use Drupal\consumers\Entity\ConsumerInterface;
use Drupal\simple_oauth_magic_link\ConsumerAdapterInterface;

/**
 * Interface for the consumer adapter service.
 */
interface ConsumerAdapterServiceInterface {

  /**
   * Gets the consumer adapter for the given consumer.
   */
  public function getConsumerAdapter(ConsumerInterface $consumer): ConsumerAdapterInterface;

}
