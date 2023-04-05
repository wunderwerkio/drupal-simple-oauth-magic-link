<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_magic_link;

use Drupal\consumers\Entity\ConsumerInterface;

/**
 * Interface for the consumers entity adapter.
 */
interface ConsumerAdapterInterface {

  /**
   * Create a new ConsumerAdapter object.
   *
   * @param \Drupal\consumers\Entity\ConsumerInterface $consumer
   *   The consumer entity.
   *
   * @return static
   *   The new ConsumerAdapter object.
   */
  public static function create(ConsumerInterface $consumer): self;

  /**
   * Checks if Authorization Code Grant is enabled for the client.
   *
   * @return bool
   *   TRUE if the Authorization Code Grant is enabled for the client,
   *   FALSE otherwise.
   */
  public function isAuthCodeGrantEnabledForClient(): bool;

  /**
   * Checks if PKCE is enabled for the client.
   *
   * @return bool
   *   TRUE if PKCE is enabled for the client, FALSE otherwise.
   */
  public function isPkceEnabledForClient(): bool;

  /**
   * Gets the auth code expiration time as configured for the client.
   *
   * @return \DateInterval
   *   The auth code expiration time.
   */
  public function getAuthCodeExpirationTime(): \DateInterval;

  /**
   * Checks if magic link one-time login URLs are enabled for the client.
   *
   * @return bool
   *   TRUE if magic link one-time login URLs are enabled for the client,
   *   FALSE otherwise.
   */
  public function magicLinkOneTimeLoginUrlsEnabled(): bool;

  /**
   * Gets the magic link base URL as configured for the client.
   *
   * @return string|null
   *   The magic link base URL, or NULL if not configured.
   */
  public function getMagicLinkBaseUrl(): ?string;

  /**
   * Gets the magic link path template as configured for the client.
   *
   * @return string|null
   *   The magic link path template, or NULL if not configured.
   */
  public function getMagicLinkPathTemplate(): ?string;

  /**
   * Builds a magic link URL for the given auth code.
   *
   * @param string $authCode
   *   The auth code.
   * @param array $params
   *   An array of parameters to be added to the URL.
   *
   * @return string
   *   The magic link URL.
   */
  public function buildMagicLinkUrl(string $authCode, array $params): string;

}
