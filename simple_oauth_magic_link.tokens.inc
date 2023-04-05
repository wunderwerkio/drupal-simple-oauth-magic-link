<?php

/**
 * @file
 * Token definitions for simple_oauth_magic_link.
 */

use Drupal\Core\Render\BubbleableMetadata;
use Drupal\Core\StringTranslation\TranslatableMarkup;

/**
 * @file
 * Builds placeholder replacement tokens for magic-link-related data.
 *
 * The [user:one-time-login-url-or-magic-link] token should be restricted to
 * only be used in emails sent to the user account owner.
 * This is done by registering a public token that replaces itself with a
 * private token [user:one-time-login-url-or-magic-link_mail-only].
 * This private token is then replaced by a custom token handler.
 * @see simple_oauth_magic_link_user_mail_tokens().
 */

/**
 * Implements hook_token_info().
 */
function simple_oauth_magic_link_token_info() {
  $info = [
    'tokens' => [
      'user' => [
        'magic-link-login' => [
          'name' => new TranslatableMarkup('Magic Link'),
          'description' => new TranslatableMarkup('A magic link for a one time login.'),
          'restricted' => TRUE,
        ],
        'magic-link-password-reset' => [
          'name' => new TranslatableMarkup('Magic Link for Password Reset'),
          'description' => new TranslatableMarkup('A magic link with additional params for password reset.'),
          'restricted' => TRUE,
        ],
      ],
    ],
  ];

  return $info;
}

/**
 * Implements hook_tokens().
 */
function simple_oauth_magic_link_tokens($type, $tokens, array $data, array $options, BubbleableMetadata $bubbleable_metadata) {
  $replacements = [];

  if ($type == 'user' && !empty($data['user'])) {
    foreach ($tokens as $name => $original) {
      switch ($name) {
        case 'magic-link-login':
          $replacements[$original] = '[user:magic-link-login_mail-only]';
          break;

        case 'magic-link-password-reset':
          $replacements[$original] = '[user:magic-link-password-reset_mail-only]';
          break;
      }
    }
  }

  return $replacements;
}
