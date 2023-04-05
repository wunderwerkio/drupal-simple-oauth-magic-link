<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_magic_link\Service;

use Drupal\Core\Session\AccountInterface;

/**
 * Interface for the auth code generator.
 */
interface AuthCodeGeneratorInterface {

  /**
   * Generates an auth code for a given client and user.
   *
   * @param string $clientId
   *   The ID of the client to use. This is the consumer ID in drupal.
   * @param \Drupal\Core\Session\AccountInterface $user
   *   The user to generate the auth code for.
   *
   * @return string
   *   The encrypted auth code payload. This token can be used in the
   *   authorization_code grant type as the value of the code field.
   */
  public function generateAuthCode(string $clientId, AccountInterface $user): string;

}
