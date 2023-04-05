<?php

declare(strict_types=1);

namespace Drupal\simple_oauth_magic_link\Service;

use Defuse\Crypto\Core;
use Defuse\Crypto\Crypto;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Site\Settings;
use Drupal\simple_oauth\Entities\ClientEntityInterface;
use Drupal\simple_oauth_magic_link\ConsumerAdapterInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Grant\AbstractGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

/**
 * Service to generate auth codes.
 */
class AuthCodeGenerator implements AuthCodeGeneratorInterface {

  /**
   * Constructs a new AuthCodeGenerator object.
   *
   * @param \League\OAuth2\Server\Repositories\ClientRepositoryInterface $clientRepository
   *   The client repository.
   * @param \League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface $authCodeRepository
   *   The auth code repository.
   * @param \Drupal\simple_oauth_magic_link\Service\ConsumerAdapterServiceInterface $consumerAdapterService
   *   The consumer adapter service.
   */
  public function __construct(
    protected ClientRepositoryInterface $clientRepository,
    protected AuthCodeRepositoryInterface $authCodeRepository,
    protected ConsumerAdapterServiceInterface $consumerAdapterService,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function generateAuthCode(string $clientId, AccountInterface $user): string {
    $clientEntity = $this->clientRepository->getClientEntity($clientId);
    if (!$clientEntity) {
      throw new \Exception(sprintf('Client with id "%s" not found', $clientId));
    }

    $consumerAdapter = $this->getConsumerAdapter($clientEntity);

    // Auth code will not be generated if the client does not support
    // the authorization code grant.
    if (!$consumerAdapter->isAuthCodeGrantEnabledForClient()) {
      throw new \Exception(sprintf('Client with id "%s" does not support the authorization code grant', $clientId));
    }

    // @todo Support PKCE clients.
    if ($consumerAdapter->isPkceEnabledForClient()) {
      throw new \Exception('The AuthCodeGenerator does not support PKCE clients');
    }

    $expiryTime = (new \DateTimeImmutable())->add(
      $consumerAdapter->getAuthCodeExpirationTime()
    );

    $authCode = $this->authCodeRepository->getNewAuthCode();
    $authCode->setExpiryDateTime($expiryTime);
    $authCode->setClient($clientEntity);

    // The user identifier is the user ID.
    // @see \Drupal\simple_oauth\Controller\Oauth2AuthorizeController::authorize()
    $authCode->setUserIdentifier($user->id());

    // Generate a unique identifier for the auth code.
    $maxGenerationAttempts = AbstractGrant::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
    while ($maxGenerationAttempts-- > 0) {
      $authCode->setIdentifier($this->generateUniqueIdentifier());
      try {
        $this->authCodeRepository->persistNewAuthCode($authCode);
        break;
      }
      catch (UniqueTokenIdentifierConstraintViolationException $e) {
        if ($maxGenerationAttempts === 0) {
          throw $e;
        }
      }
    }

    return $this->encryptAuthCode($authCode);
  }

  /**
   * Creates an encrypted json payload containing the auth code data.
   *
   * Payload must conform to structure expected by decryptAuthCode().
   *
   * @param \League\OAuth2\Server\Entities\AuthCodeEntityInterface $authCode
   *   The auth code entity.
   *
   * @return string
   *   The encrypted auth code.
   *
   * @see \League\OAuth2\Server\Grant\AbstractGrant::completeAuthorizationRequest()
   */
  protected function encryptAuthCode(AuthCodeEntityInterface $authCode): string {
    $payload = [
      'client_id' => $authCode->getClient()->getIdentifier(),
      'redirect_uri' => $authCode->getRedirectUri(),
      'auth_code_id' => $authCode->getIdentifier(),
      'scopes' => $authCode->getScopes(),
      'user_id' => $authCode->getUserIdentifier(),
      'expire_time' => $authCode->getExpiryDateTime()->getTimestamp(),
    ];

    $jsonPayload = json_encode($payload);
    $encryptedAuthCode = Crypto::encryptWithPassword($jsonPayload, $this->getEncryptionKey());

    return $encryptedAuthCode;
  }

  /**
   * Generate a new unique identifier.
   *
   * This is taken from the oauth2_server package.
   *
   * @param int $length
   *   The length of the identifier to generate.
   *
   * @throws \League\OAuth2\Server\Exception\OAuthServerException
   *   When the identifier could not be generated.
   *
   * @return string
   *   The generated identifier.
   *
   * @see \League\OAuth2\Server\Grant\AbstractGrant::generateUniqueIdentifier()
   */
  protected function generateUniqueIdentifier($length = 40) {
    try {
      return \bin2hex(\random_bytes($length));
    }
    catch (\TypeError $e) {
      throw OAuthServerException::serverError('An unexpected error has occurred', $e);
    }
    catch (\Error $e) {
      throw OAuthServerException::serverError('An unexpected error has occurred', $e);
    }
    catch (\Exception $e) {
      // If you get this message, the CSPRNG failed hard.
      throw OAuthServerException::serverError('Could not generate a random string', $e);
    }
  }

  /**
   * Gets the encryption key.
   *
   * This is taken from the simple_oauth module.
   *
   * @return string
   *   The encryption key.
   *
   * @throws \League\OAuth2\Server\Exception\OAuthServerException
   *   Thrown when the hash salt is not at least 32 characters long.
   *
   * @see \Drupal\simple_oauth\Server\AuthorizationServerFactory
   */
  protected function getEncryptionKey() {
    $salt = Settings::getHashSalt();

    // The hash salt must be at least 32 characters long.
    if (Core::ourStrlen($salt) < 32) {
      throw OAuthServerException::serverError('Hash salt must be at least 32 characters long.');
    }

    return Core::ourSubstr($salt, 0, 32);
  }

  /**
   * Gets the consumer adapter.
   *
   * @param \Drupal\simple_oauth\Entities\ClientEntityInterface $clientEntity
   *   The client entity.
   *
   * @return \Drupal\simple_oauth\ConsumerAdapterInterface
   *   The consumer adapter.
   */
  protected function getConsumerAdapter(ClientEntityInterface $clientEntity): ConsumerAdapterInterface {
    return $this->consumerAdapterService->getConsumerAdapter($clientEntity->getDrupalEntity());
  }

}
