<?php

/**
 * Wrapper framework for OAuth2 with included providers.
 *
 * @author Stian Hanger <pdnagilum@gmail.com>
 *
 * ---
 *
 * Released under the MIT license.
 *
 * Copyright (c) 2013 Stian Hanger
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

namespace OAuth2;

define('ACCESS_TOKEN',          'access_token');
define('AUTHENTICATION_CODE',   'authorization_code');
define('ERROR_CODE',            'error');
define('ERROR_DESC',            'error_description');
define('HAS_ACCESS_TOKEN',      'has_access_token');
define('HAS_USER_INFO',         'has_user_info');
define('HTTP_METHOD_GET',       'GET');
define('HTTP_METHOD_POST',      'POST');
define('IS_AUTHORIZED',         'is_authorized');
define('OAUTH_URL_AUTH',        'authorize');
define('OAUTH_URL_TOKEN',       'token');
define('OAUTH_URL_USER',        'user');
define('OAUTH_URL_USER_HEADER', 'user_header');
define('REFRESH_TOKEN',         'refresh_token');
define('RESPONSE_TYPE_CODE',    'code');
define('SCOPE',                 'scope');
define('TOKEN_TYPE',            'token_type');
define('UNIQUE_ID',             'unique_id');
define('USER_INFO',             'user_info');

/**
 * The main OAuth client class.
 */
class Client {
  /**
   * Authorization code.
   *
   * The authorization code return from the provider after the first
   * successfull login.
   *
   * @var string
   */
  protected $authorizationCode = NULL;

  /**
   * Client ID.
   *
   * The client ID given by the provider when creating an app.
   *
   * @var string
   */
  protected $clientID          = NULL;

  /**
   * Client secret.
   *
   * The client secret given by the provider when creating an app.
   *
   * @var string
   */
  protected $clientSecret      = NULL;

  /**
   * Provider.
   *
   * The shorthand name of the provider to use.
   *
   * @var string
   */
  protected $provider          = NULL;

  /**
   * Redirect URI.
   *
   * The URL given to the provider at first authorization-call that they will
   * send you back to with a valid authorization code, if login is successfull.
   *
   * @var string
   */
  protected $redirectURI       = NULL;

  /**
   * A list of public variables (read only) the are available from outside the
   * library. Use $instance->var_name to access them. A list of the real names
   * can be found in the define list at the start of this file.
   *
   * @var array
   */
  protected $public = array(
    ACCESS_TOKEN     => NULL,
    HAS_ACCESS_TOKEN => FALSE,
    HAS_USER_INFO    => FALSE,
    IS_AUTHORIZED    => FALSE,
    REFRESH_TOKEN    => NULL,
    TOKEN_TYPE       => NULL,
    UNIQUE_ID        => NULL,
    USER_INFO        => array(),
    );

  /**
   * A list of all configured endpoints for providers.
   *
   * @var array
   */
  protected $endpoints = array(
    'bitly' => array(
      OAUTH_URL_AUTH  => 'https://bitly.com/oauth/authorize',
      OAUTH_URL_TOKEN => 'https://api-ssl.bitly.com/oauth/access_token',
      OAUTH_URL_USER  => 'https://api-ssl.bitly.com/v3/user/info',
      ),
    'facebook' => array(
      OAUTH_URL_AUTH  => 'https://graph.facebook.com/oauth/authorize',
      OAUTH_URL_TOKEN => 'https://graph.facebook.com/oauth/access_token',
      OAUTH_URL_USER  => 'https://graph.facebook.com/me',
      ),
    'github' => array(
      OAUTH_URL_AUTH  => 'https://github.com/login/oauth/authorize',
      OAUTH_URL_TOKEN => 'https://github.com/login/oauth/access_token',
      OAUTH_URL_USER  => 'https://api.github.com/user',
      ),
    'google' => array(
      OAUTH_URL_AUTH  => 'https://accounts.google.com/o/oauth2/auth',
      OAUTH_URL_TOKEN => 'https://accounts.google.com/o/oauth2/token',
      OAUTH_URL_USER  => 'https://www.googleapis.com/oauth2/v2/userinfo',
      ),
    'live' => array(
      OAUTH_URL_AUTH  => 'https://login.live.com/oauth20_authorize.srf',
      OAUTH_URL_TOKEN => 'https://login.live.com/oauth20_token.srf',
      OAUTH_URL_USER  => 'https://apis.live.net/v5.0/me',
      ),
    'wordpress' => array(
      OAUTH_URL_AUTH  => 'https://public-api.wordpress.com/oauth2/authorize',
      OAUTH_URL_TOKEN => 'https://public-api.wordpress.com/oauth2/token',
      OAUTH_URL_USER  => 'https://public-api.wordpress.com/rest/v1/me/?pretty=1',
      OAUTH_URL_USER_HEADER => TRUE,
      ),
    );

  /**
   * Construct.
   *
   * @param string $clientID
   *   Client ID.
   * @param string $clientSecret
   *   Client secret.
   * @param string $provider
   *   Short hand name for the provider.
   * @param string $redirectURI
   *   (optional) The redirect URI to use when authorizing first login. If no
   *   URI is given, the library tries to build one from the _SERVER array.
   * @param array $endpoints
   *   (optional) Additional endpoints to add to the list of available providers
   *   and endpoints.
   * @param string $refreshToken
   *   Saved token to try and refresh the authorization so you won't have to go
   *   through the authorization process again.
   */
  public function __construct($clientID, $clientSecret, $provider, $redirectURI = NULL, $endpoints = array(), $refreshToken = NULL) {
    $this->clientID = $clientID;
    $this->clientSecret = $clientSecret;
    $this->provider = $provider;
    $this->redirectURI = $redirectURI;

    if (is_array($endpoints) &&
        count($endpoints)) {
      foreach ($endpoints as $provider => $urls) {
        $this->endpoints[$provider] = $urls;
      }
    }

    $this->public[REFRESH_TOKEN] = $refreshToken;

    if ($this->redirectURI == NULL ||
        empty($this->redirectURI))
      $this->redirectURI =
      'http' .
      (isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on' ? 's' : '') .
      '://' .
      $_SERVER['HTTP_HOST'] .
      '/';

    $this->handlePageRequest();
  }

  /**
   * Reads the value of the given variable in the public array.
   *
   * @param string $name
   *   The name of the variable to retrieve.
   *
   * @return var
   */
  public function __get($name) {
    if (isset($this->public[$name]))
      return $this->public[$name];

    return FALSE;
  }

  /**
   * Initiate the authorization process by redirecting to the provider.
   *
   * Builds the authorization URL and redirects the browser there.
   *
   * @param array $scope
   *   Scope to add to the authorization process.
   */
  public function authorize($scope = NULL) {
    $parameters = array(
      'client_id'     => $this->clientID,
      'display'       => 'page',
      'locale'        => 'en',
      'redirect_uri'  => $this->redirectURI,
      'response_type' => RESPONSE_TYPE_CODE,
      );

    if (!empty($scope)) {
      if (is_array($scope))
        $scope = implode(' ', $scope);

      $parameters['scope'] = $scope;
    }

    $parameters['state'] = rawurlencode(
      $this->buildQueryString(
        array(
          'redirect_type' => 'auth',
          'display' => 'page',
          'request_ts' => time(),
          'response_method' => 'cookie',
          'secure_cookie' => 'false',
          )
        )
      );

    $url =
      $this->endpoints[$this->provider][OAUTH_URL_AUTH] . '?' .
      $this->buildQueryString($parameters);

    header('Location: ' . $url);
    exit;
  }

  /**
   * Builds a single query string from an array of content.
   *
   * @param array $array
   *   A list of variables to build from.
   *
   * @return string
   *   The compilled query string.
   */
  protected function buildQueryString($array) {
    $result = '';
    $prefix = '';

    foreach ($array as $key => $value) {
      $result .= $prefix . rawurlencode($key) . '=' . rawurlencode($value);

      if ($prefix == '')
        $prefix = '&';
    }

    return $result;
  }

  /**
   * Gets a list of providers from the endpoint array.
   *
   * @return array
   *   A list of providers.
   */
  public function getProviders() {
    $providers = array();

    if (count($this->endpoints)) {
      foreach ($this->endpoints as $provider => $endpoints) {
        $providers[] = $provider;
      }
    }

    return $providers;
  }

  /**
   * The main handler for the authorization process.
   *
   * It will verify the authorization code and try to retrieve an access token
   * for further use. If a refresh token is provided a backhand call is made to
   * try and verify it.
   *
   * After the access token has been retrieved, a call will be attempted to
   * retrieve user-information from the provider.
   */
  protected function handlePageRequest() {
    if (!empty($_GET[ACCESS_TOKEN]))
      return;

    $verifier = $_GET[RESPONSE_TYPE_CODE];

    if (!empty($verifier)) {
      $this->authorizationCode = $verifier;
      $this->public[IS_AUTHORIZED] = TRUE;

      $token = $this->requestAccessTokenByVerifier($verifier);

      if ($token !== FALSE) {
        $this->handleTokenResponse($token);

        $response = $this->requestUserInformation();

        if ($response !== FALSE)
          $this->handleUserInformation($response);
      }
      else
        $this->handleTokenResponse(
          NULL,
          array(
            ERROR_CODE => 'request_failed',
            ERROR_DESC => 'Failed to retrieve user access token.',
            )
          );

      return;
    }

    $refreshToken = $this->public[REFRESH_TOKEN];

    if (!empty($refreshToken)) {
      $token = $this->requestAccessTokenByRefreshToken($refreshToken);

      if ($token !== FALSE)
        $this->handleTokenResponse($token);
      else
        $this->handleTokenResponse(
          NULL,
          array(
            ERROR_CODE => 'request_failed',
            ERROR_DESC => 'Failed to retrieve refresh token.',
            )
          );

      return;
    }
  }

  /**
   * Stores the given token in the public array.
   *
   * @param array $token
   *   The token-array to save.
   * @param array $error
   *   The error information.
   */
  protected function handleTokenResponse($token, $error = NULL) {
    if (!empty($token)) {
      $this->public[ACCESS_TOKEN]     = $token[ACCESS_TOKEN];
      $this->public[HAS_ACCESS_TOKEN] = TRUE;
      $this->public[REFRESH_TOKEN]    = (isset($token[REFRESH_TOKEN]) ? $token[REFRESH_TOKEN] : NULL);
      $this->public[TOKEN_TYPE]       = (isset($token[TOKEN_TYPE]) ? $token[TOKEN_TYPE] : 'Bearer');
    }
  }

  /**
   * Stores the user-information in the public array.
   *
   * @param json $response
   *   The response object from the provider.
   */
  protected function handleUserInformation($response) {
    $userInfo = (array) json_decode($response);

    if (empty($userInfo))
      $userInfo = $this->parseQueryString($response);

    $this->public[HAS_USER_INFO] = TRUE;
    $this->public[USER_INFO]     = $userInfo;

    if (isset($userInfo['id']))
      $this->public[UNIQUE_ID] = $userInfo['id'];
  }

  /**
   * Splits up a query string into an array.
   *
   * @param string $query
   *   The query string to split up.
   *
   * @return array
   *   A list of the variables and their values from the query string.
   */
  protected function parseQueryString($query) {
    $result = array();
    $arr = preg_split('/&/', $query);

    foreach ($arr as $arg) {
      if (strpos($arg, '=') !== FALSE) {
        $kv = preg_split('/=/', $arg);
        $result[rawurldecode($kv[0])] = rawurldecode($kv[1]);
      }
    }

    return $result;
  }

  /**
   * Attempts to retrieve an access token from the provider.
   *
   * @param array $content
   *   An array of parameters to send along with the call.
   *
   * @return array
   *   The token from the provider.
   */
  protected function requestAccessToken($content) {
    $response = $this->sendRequest(
      $this->endpoints[$this->provider][OAUTH_URL_TOKEN],
      HTTP_METHOD_POST,
      $content
      );

    if ($response !== FALSE) {
      $authToken = (array) json_decode($response);

      if (empty($authToken))
        $authToken = $this->parseQueryString($response);

      if (!empty($authToken) &&
          !empty($authToken[ACCESS_TOKEN]))
        return $authToken;
    }

    return FALSE;
  }

  /**
   * Attempts to retrieve an access token via a refresh token.
   *
   * @param string $refreshToken
   *   The refresh token to use.
   *
   * @return array
   *   The access token array.
   */
  protected function requestAccessTokenByRefreshToken($refreshToken) {
    return $this->requestAccessToken(
      array(
        'client_id'     => $this->clientID,
        'redirect_uri'  => $this->redirectURI,
        'client_secret' => $this->clientSecret,
        'refresh_token' => $refreshToken,
        'grant_type'    => REFRESH_TOKEN,
        )
      );
  }

  /**
   * Attempts to retrieve an access token from the provider.
   *
   * @param string $verifier
   *   The authorization code to use.
   *
   * @return array
   *   The access token array.
   */
  protected function requestAccessTokenByVerifier($verifier) {
    return $this->requestAccessToken(
      array(
        'client_id'     => $this->clientID,
        'redirect_uri'  => $this->redirectURI,
        'client_secret' => $this->clientSecret,
        'code'          => $verifier,
        'grant_type'    => AUTHENTICATION_CODE
        )
      );
  }

  /**
   * Attempts to retrieve user information from the provider.
   *
   * @return array
   *   The provided information.
   */
  protected function requestUserInformation() {
    if (isset($this->endpoints[$this->provider][OAUTH_URL_USER]) &&
        !empty($this->endpoints[$this->provider][OAUTH_URL_USER])) {
      $useContext = (isset($this->endpoints[$this->provider][OAUTH_URL_USER_HEADER]) ? $this->endpoints[$this->provider][OAUTH_URL_USER_HEADER] : FALSE);

      return $this->sendRequest(
        $this->endpoints[$this->provider][OAUTH_URL_USER] . (!$useContext ? '?' . ACCESS_TOKEN . '=' . $this->public[ACCESS_TOKEN] : ''),
        HTTP_METHOD_GET,
        array(),
        array(
          'Authorization: ' . $this->public[TOKEN_TYPE] . ' ' . $this->public[ACCESS_TOKEN],
          ),
        $useContext
        );
    }

    return FALSE;
  }

  /**
   * The main send routine for all calls.
   *
   * @param string $url
   *   The URL to call.
   * @param string $method
   *   (optional) The HTTP method to use. Default: 'GET'.
   * @param array $data
   *   (optional) An array of data variables to send along. Default: array().
   * @param array $headers
   *   (optional) An array of headers to send along. Default: array().
   * @param bool $useContext
   *   (optional) Whether or not to include headers and data variables. Default: TRUE.
   *
   * @return string
   *   The response content from the URL.
   */
  protected function sendRequest($url, $method = HTTP_METHOD_GET, $data = array(), $headers = array(), $useContext = TRUE) {
    if ($useContext) {
      $content = '';

      if (count($data))
        $content = $this->buildQueryString($data);

      $headers[] = 'Content-type: application/x-www-form-urlencoded;charset=UTF-8';
      $headers[] = 'Content-length: ' . strlen($content);

      $context = stream_context_create(
        array(
          'http' => array(
            'method'  => $method,
            'header'  => $headers,
            'content' => $content,
            'length'  => strlen($content),
            )
          )
        );
      return file_get_contents($url, FALSE, $context);
    }
    else
      return file_get_contents($url);
  }
}
