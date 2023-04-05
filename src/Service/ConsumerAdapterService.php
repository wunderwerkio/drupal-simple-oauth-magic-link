<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_magic_link\Service;

use Drupal\consumers\Entity\ConsumerInterface;
use Drupal\simple_oauth_magic_link\ConsumerAdapter;
use Drupal\simple_oauth_magic_link\ConsumerAdapterInterface;

/**
 * This class provides the consumer adapter.
 */
class ConsumerAdapterService implements ConsumerAdapterServiceInterface {

  /**
   * {@inheritdoc}
   */
  public function getConsumerAdapter(ConsumerInterface $consumer): ConsumerAdapterInterface {
    return ConsumerAdapter::create($consumer);
  }

}
