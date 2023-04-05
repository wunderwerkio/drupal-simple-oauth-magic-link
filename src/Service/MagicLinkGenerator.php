<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_magic_link\Service;

use Drupal\consumers\Entity\ConsumerInterface;
use Drupal\consumers\Negotiator;
use Drupal\Core\Session\AccountInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Service for generating magic links.
 */
class MagicLinkGenerator implements MagicLinkGeneratorInterface {

  /**
   * Create a new MagicLinkGenerator object.
   *
   * @param \Drupal\simple_oauth_magic_link\Service\AuthCodeGeneratorInterface $authCodeGenerator
   *   The auth code generator service.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack.
   * @param \Drupal\consumers\Negotiator $consumerNegotiator
   *   The consumer negotiator service.
   * @param \Psr\Log\LoggerInterface $logger
   *   The logger service.
   * @param \Drupal\simple_oauth_magic_link\Service\ConsumerAdapterServiceInterface $consumerAdapterService
   *   The consumer adapter service.
   */
  public function __construct(
    protected AuthCodeGeneratorInterface $authCodeGenerator,
    protected RequestStack $requestStack,
    protected Negotiator $consumerNegotiator,
    protected LoggerInterface $logger,
    protected ConsumerAdapterServiceInterface $consumerAdapterService,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function generateUrl(AccountInterface $account, array $options = []): string {
    $currentRequest = $this->requestStack->getCurrentRequest();
    $consumer = $this->consumerNegotiator->negotiateFromRequest($currentRequest);

    return $this->generateUrlForConsumer($account, $consumer, $options);
  }

  /**
   * {@inheritdoc}
   */
  public function generateUrlByClientId(AccountInterface $account, string $clientId, array $options = []): string {
    $storage = \Drupal::service('entity_type.manager')->getStorage('consumer');
    $entities = $storage->loadByProperties(['client_id' => $clientId]);
    $consumer = reset($entities);

    return $this->generateUrlForConsumer($account, $consumer, $options);
  }

  /**
   * Generates a magic link for the given consumer and user.
   *
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account to generate the URL for.
   * @param \Drupal\consumers\Entity\ConsumerInterface|false $consumer
   *   The consumer entity.
   * @param array $options
   *   An array of options.
   *
   * @return string
   *   The generated URL.
   */
  protected function generateUrlForConsumer(AccountInterface $account, ConsumerInterface|false $consumer, array $options = []): string {
    if (!$consumer) {
      $this->logger->error('No consumer could be determined for the current request!');

      return '';
    }

    $consumerAdapter = $this->consumerAdapterService->getConsumerAdapter($consumer);

    // If the consumer has enabled magic links, generate a magic link.
    if ($consumerAdapter->magicLinkOneTimeLoginUrlsEnabled()) {
      $authCode = $this->authCodeGenerator->generateAuthCode($consumer->getClientId(), $account);

      return $consumerAdapter->buildMagicLinkUrl($authCode, $options);
    }

    $this->logger->warning('The negotiated consumer does not have magic links enabled:  %consumer', ['%consumer' => $consumer->label()]);
    return '';
  }

}
