<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_magic_link;

use Drupal\consumers\Entity\ConsumerInterface;

/**
 * An adapter for the consumers entity.
 */
class ConsumerAdapter implements ConsumerAdapterInterface {

  /**
   * Create a new ConsumerAdapter object.
   *
   * @param \Drupal\consumers\Entity\ConsumerInterface $consumer
   *   The consumer entity.
   */
  public function __construct(
    protected ConsumerInterface $consumer,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ConsumerInterface $consumer): self {
    return new static($consumer);
  }

  /**
   * {@inheritdoc}
   */
  public function isAuthCodeGrantEnabledForClient(): bool {
    return array_reduce($this->consumer->get('grant_types')->getValue(), function ($carry, $item) {
      if ($item['value'] === 'authorization_code') {
        return TRUE;
      }

      return $carry;
    }, FALSE);
  }

  /**
   * {@inheritdoc}
   */
  public function isPkceEnabledForClient(): bool {
    return (bool) $this->consumer->get('pkce')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getAuthCodeExpirationTime(): \DateInterval {
    $seconds = $this->consumer->get('magic_link_auth_code_expiration')->value ?? 1800;

    return new \DateInterval(sprintf('PT%dS', $seconds));
  }

  /**
   * {@inheritdoc}
   */
  public function magicLinkOneTimeLoginUrlsEnabled(): bool {
    return (bool) $this->consumer->get('magic_link_one_time_login_urls_enabled')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getMagicLinkBaseUrl(): ?string {
    return $this->consumer->get('magic_link_base_url')->getString();
  }

  /**
   * {@inheritdoc}
   */
  public function getMagicLinkPathTemplate(): ?string {
    return $this->consumer->get('magic_link_path_template')->getString();
  }

  /**
   * {@inheritdoc}
   */
  public function buildMagicLinkUrl(string $authCode, array $params): string {
    $baseUrl = $this->getMagicLinkBaseUrl();
    $pathTemplate = $this->getMagicLinkPathTemplate();

    if (!$baseUrl || !$pathTemplate) {
      throw new \RuntimeException('Magic link base URL and path template must be configured for the client.');
    }

    $url = sprintf('%s%s', $baseUrl, str_replace('{code}', $authCode, $pathTemplate));

    // Add query parameters.
    if (!empty($params)) {
      $url .= '?' . http_build_query($params);
    }

    return $url;
  }

}
