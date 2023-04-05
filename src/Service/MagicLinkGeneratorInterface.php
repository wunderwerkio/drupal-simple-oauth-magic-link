<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_magic_link\Service;

use Drupal\Core\Session\AccountInterface;

/**
 * Interface for the magic link generator.
 */
interface MagicLinkGeneratorInterface {

  /**
   * Generates a magic link for a given user and consumer.
   *
   * The URL generated is depending on the active consumer, which is
   * determined by the current request.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The user to generate the URL for.
   * @param array $options
   *   (optional) A keyed array of settings. Supported options are:
   *   - langcode: A language code to be used when generating locale-sensitive
   *    URLs. If langcode is NULL the users preferred language is used.
   *
   * @return string
   *   The generated magic link.
   */
  public function generateUrl(AccountInterface $account, array $options = []): string;

  /**
   * Generates a magic link for a given user and consumer by client id.
   *
   * The URL generated is depending on the active consumer, which is
   * determined by the current request.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The user to generate the URL for.
   * @param string $clientId
   *   The client id of the consumer.
   * @param array $options
   *   (optional) A keyed array of settings. Supported options are:
   *   - langcode: A language code to be used when generating locale-sensitive
   *    URLs. If langcode is NULL the users preferred language is used.
   *
   * @return string
   *   The generated magic link.
   */
  public function generateUrlByClientId(AccountInterface $account, string $clientId, array $options = []): string;

}
