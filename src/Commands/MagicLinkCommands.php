<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_magic_link\Commands;

use Drupal\Component\Utility\Crypt;
use Drupal\simple_oauth_magic_link\Service\AuthCodeGeneratorInterface;
use Drupal\simple_oauth_magic_link\Service\MagicLinkGeneratorInterface;
use Drupal\user\Entity\User;
use Drush\Commands\DrushCommands;

/**
 * Drush commands for the Simple OAuth Magic Link module.
 */
class MagicLinkCommands extends DrushCommands {

  /**
   * Create a new MagicLinkCommands object.
   *
   * @param \Drupal\simple_oauth_magic_link\Service\AuthCodeGeneratorInterface $authCodeGenerator
   *   The auth code generator service.
   * @param \Drupal\simple_oauth_magic_link\Service\MagicLinkGeneratorInterface $magicLinkGenerator
   *   The one time login url generator service.
   */
  public function __construct(
    protected AuthCodeGeneratorInterface $authCodeGenerator,
    protected MagicLinkGeneratorInterface $magicLinkGenerator,
  ) {}

  /**
   * Generates an auth code for a given client and user.
   *
   * @param array $options
   *   The command options.
   *
   * @command simple-oauth:magic-link-generate-auth-code
   * @aliases soml-gac
   * @option client_id The ID of the client to use. This is the consumer ID in drupal.
   * @option uid The user to generate the auth code for.
   * @usage drush magic-link:generate-auth-code --client_id=123 --uid=1
   */
  public function generateAuthCode(array $options = [
    'client_id' => NULL,
    'uid' => NULL,
  ]) {
    if (!$options['client_id']) {
      throw new \Exception('The client_id option is required.');
    }

    if (!$options['uid']) {
      throw new \Exception('The uid option is required.');
    }

    $clientId = $options['client_id'];
    $user = User::load($options['uid']);

    if (!$user) {
      throw new \Exception(sprintf('The user with uid %s could not be loaded.', $options['uid']));
    }

    $authCode = $this->authCodeGenerator->generateAuthCode($clientId, $user);

    $this->writeln($authCode);
  }

  /**
   * Generates a magic link for a given client and user.
   *
   * @param array $options
   *   The command options.
   *
   * @command simple-oauth:generate-magic-link
   * @aliases ml
   * @option client_id The ID of the client to use. This is the consumer ID in drupal.
   * @option uid The user to generate the magic link for.
   * @usage drush magic-link:generate-magic-link --client_id=123 --uid=1
   */
  public function userLoginUrl(array $options = [
    'client_id' => NULL,
    'uid' => NULL,
  ]) {
    if (!$options['client_id']) {
      throw new \Exception('The client_id option is required.');
    }

    if (!$options['uid']) {
      throw new \Exception('The uid option is required.');
    }

    $clientId = $options['client_id'];
    $user = User::load($options['uid']);

    if (!$user) {
      throw new \Exception(sprintf('The user with uid %s could not be loaded.', $options['uid']));
    }

    $url = $this->magicLinkGenerator->generateUrlByClientId($user, $clientId, []);

    $this->writeln($url);
  }

}
