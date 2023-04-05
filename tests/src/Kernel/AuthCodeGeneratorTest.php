<?php

declare(strict_types=1);

namespace Drupal\Tests\simple_oauth_magic_link\Kernel;

use Defuse\Crypto\Core;
use Defuse\Crypto\Crypto;
use Drupal\consumers\Entity\Consumer;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\Core\Entity\EntityKernelTestBase;
use Drupal\simple_oauth_magic_link\Service\AuthCodeGeneratorInterface;
use Drupal\Tests\simple_oauth\Functional\SimpleOauthTestTrait;

/**
 * Tests the auth code generator.
 *
 * @group simple_oauth_magic_link
 */
class AuthCodeGeneratorTest extends EntityKernelTestBase {

  use SimpleOauthTestTrait;

  protected const CLIENT_ID = 'test_client';

  /**
   * The user to generate the auth code for.
   *
   * @var \Drupal\Core\Session\AccountInterface
   */
  protected AccountInterface $user;

  /**
   * Auth code generator.
   *
   * @var \Drupal\simple_oauth_magic_link\Service\AuthCodeGeneratorInterface
   */
  protected AuthCodeGeneratorInterface $authCodeGenerator;

  /**
   * The client secret.
   *
   * @var string
   */
  protected string $clientSecret;

  /**
   * The client.
   *
   * @var \Drupal\consumers\Entity\Consumer
   */
  protected Consumer $client;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'serialization',
    'consumers',
    'file',
    'options',
    'image',
    'simple_oauth',
    'simple_oauth_magic_link',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installEntitySchema('consumer');
    $this->installEntitySchema('oauth2_token');
    $this->installEntitySchema('user');
    $this->installConfig(['user']);
    $this->installConfig(['simple_oauth']);

    mkdir($this->siteDirectory . '/keys', 0775);
    $public_key_path = "{$this->siteDirectory}/keys/public.key";
    $private_key_path = "{$this->siteDirectory}/keys/private.key";

    file_put_contents($public_key_path, $this->publicKey);
    file_put_contents($private_key_path, $this->privateKey);
    chmod($public_key_path, 0660);
    chmod($private_key_path, 0660);

    $settings = $this->config('simple_oauth.settings');
    $settings->set('public_key', $public_key_path);
    $settings->set('private_key', $private_key_path);
    $settings->save();

    $this->user = $this->drupalCreateUser();

    $this->clientSecret = $this->randomString();

    $this->client = Consumer::create([
      'client_id' => self::CLIENT_ID,
      'label' => 'test',
      'grant_types' => [
        'authorization_code',
      ],
      'secret' => $this->clientSecret,
      'magic_link_auth_code_expiration_time' => 1800,
    ]);
    $this->client->save();

    $this->authCodeGenerator = $this->container->get('simple_oauth_magic_link.service.auth_code_generator');
  }

  /**
   * Tests the auth code generator.
   */
  public function testGenerateAuthCode(): void {
    $now = time();
    $authCode = $this->authCodeGenerator->generateAuthCode(self::CLIENT_ID, $this->user);
    $this->assertNotNull($authCode);

    $payload = $this->decryptAuthCode($authCode);

    // Get magic link auth code expiration time from client.
    $expirationTime = (int) $this->client->get('magic_link_auth_code_expiration')->value;

    // Create a timestamp that is $expirationTime seconds into the future.
    $timestamp = $expirationTime + $now;

    $this->assertEquals(self::CLIENT_ID, $payload['client_id']);
    $this->assertEquals($this->user->id(), $payload['user_id']);
    $this->assertEquals($timestamp, $payload['expire_time']);
    $this->assertEmpty($payload['scopes']);
    $this->assertNull($payload['redirect_uri']);
  }

  /**
   * Tests the auth code generator with an invalid client.
   */
  public function testInvalidClient(): void {
    $this->expectException(\Exception::class);
    $this->authCodeGenerator->generateAuthCode('non_existing_client', $this->user);
  }

  /**
   * Tests with a client that doesnt support the authorization_code grant type.
   */
  public function testClientWithoutAuthCodeGrant(): void {
    $this->client->set('grant_types', ['client_credentials'])->save();

    $this->expectException(\Exception::class);
    $this->authCodeGenerator->generateAuthCode(self::CLIENT_ID, $this->user);
  }

  /**
   * Test the auth code generator with a client that has PKCE enabled.
   */
  public function testClientWithPkceEnabled(): void {
    $this->client->set('pkce', 1)->save();

    $this->expectException(\Exception::class);
    $this->authCodeGenerator->generateAuthCode(self::CLIENT_ID, $this->user);
  }

  /**
   * Decrypts an auth code.
   *
   * @param string $authCode
   *   The auth code to decrypt.
   *
   * @return array
   *   The decrypted auth code.
   */
  protected function decryptAuthCode(string $authCode): array {
    $decryptedPayload = Crypto::decryptWithPassword($authCode, Core::ourSubstr(Settings::getHashSalt(), 0, 32));

    return json_decode($decryptedPayload, TRUE);
  }

}
