<?php

/**
 * Common include-point for OAuth v1 and v2.
 *
 * This function determines if the provider you have given supports v2 or v1
 * and operates accordingly. If you specify a provider that is not supported
 * yet, an exception will be thrown.
 *
 * @param string $clientID
 *   Client ID.
 * @param string $clientSecret
 *   Client secret.
 * @param string $provider
 *   Provider.
 * @param string $redirectUri
 *   (optional) Application redirect-uri.
 * @param array $parameters
 *   (optional) Extra parameters to send along.
 *
 * @return class
 *   The OAuth v1 or v2 class, ready for further use.
 */
function OAuthProcess($clientID, $clientSecret, $provider, string $redirectUri = NULL, array $parameters = array()) {
  $client = NULL;

  // A bit or error trapping.
  if ($clientID == NULL || empty($clientID) ||
      $clientSecret == NULL || empty($clientSecret) ||
      $provider == NULL || empty($provider))
    throw new Exception('Neither Client ID, client secret, nor provider can be blank.');

  // Compile the redirect-uri if you omitted the param.
  if ($redirectUri == NULL)
    $redirectUri =
      'http' .
      (isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on' ? 's' : '') .
      '://' .
      $_SERVER['HTTP_HOST'] .
      '/';

  // Determine which version of OAuth to use.
  switch (strtolower($provider)) {
    case 'bitly':
    case 'facebook':
    case 'github':
    case 'google':
    case 'wordpress':
      // This is required for Google so you might as well use it for the others too.
      $redirectUri .= '/oauth2callback';

      // Include the v2 lib and init the process.
      require_once 'OAuth2.php';
      $client = new OAuth2\Client($clientID, $clientSecret, $redirectUri, $provider);
      $client->process($parameters);

      break;

    default:
      throw new Exception('You have given a provider that is not yet supported by this framework.');
      break;
  }

  return $client;
}
