<?php

declare(strict_types=1);

namespace Drupal\Tests\simple_oauth_magic_link\Kernel;

use Drupal\consumers\Entity\Consumer;
use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\Core\Entity\EntityKernelTestBase;
use Drupal\simple_oauth_magic_link\Service\MagicLinkGeneratorInterface;
use Drupal\Tests\simple_oauth\Functional\SimpleOauthTestTrait;

/**
 * Test the magic link generator.
 *
 * @group simple_oauth_magic_link
 */
class MagicLinkGeneratorTest extends EntityKernelTestBase {

  use SimpleOauthTestTrait;

  protected const CLIENT_ID = 'test_client';
  protected const BASE_URL = 'https://my-drupal-head.com';
  protected const PATH_TEMPLATE = '/api/login/{code}';

  /**
   * The user to generate the auth code for.
   *
   * @var \Drupal\Core\Session\AccountInterface
   */
  protected AccountInterface $user;

  /**
   * The one time login url generator.
   *
   * @var \Drupal\simple_oauth_magic_link\Service\MagicLinkGeneratorInterface
   */
  protected MagicLinkGeneratorInterface $magicLinkGenerator;

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
      'is_default' => TRUE,
      'magic_link_one_time_login_urls_enabled' => TRUE,
      'magic_link_base_url' => self::BASE_URL,
      'magic_link_path_template' => self::PATH_TEMPLATE,
    ]);
    $this->client->save();

    $this->magicLinkGenerator = $this->container->get('simple_oauth_magic_link.service.magic_link_generator');
  }

  /**
   * Test the one time login url generation.
   */
  public function testGenerateMagicLink(): void {
    $url = $this->magicLinkGenerator->generateUrl($this->user);
    $this->assertStringStartsWith(self::BASE_URL, $url);

    // With invalid consumer.
    $url = $this->magicLinkGenerator->generateUrlByClientId($this->user, $this->client->getClientId());
    $this->assertStringStartsWith(self::BASE_URL, $url);

    // With invalid consumer.
    $url = $this->magicLinkGenerator->generateUrlByClientId($this->user, '-1');
    $this->assertEmpty($url);

    // With query parameters.
    $url = $this->magicLinkGenerator->generateUrl($this->user, [
      'param1' => 'value1',
    ]);
    $this->assertStringContainsString('?param1=value1', $url);
  }

  /**
   * Test generated url when magic link is disabled.
   */
  public function testGenerateWithMagicLinkDisabled(): void {
    $this->client->set('magic_link_one_time_login_urls_enabled', FALSE)->save();

    $url = $this->magicLinkGenerator->generateUrl($this->user);
    $this->assertStringStartsNotWith(self::BASE_URL, $url);
  }

}
