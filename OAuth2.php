<?php

/**
 * @file
 * A simple wrapper class for OAuth2.
 *
 * @author  Stian Hanger <pdnagilum@gmail.com>
 * @version 0.1-dev
 */

namespace OAuth2;

class Client {
  /**
   * HTTP Methods
   */
  const HTTP_METHOD_GET    = 'GET';
  const HTTP_METHOD_POST   = 'POST';
  const HTTP_METHOD_PUT    = 'PUT';
  const HTTP_METHOD_DELETE = 'DELETE';
  const HTTP_METHOD_HEAD   = 'HEAD';
  const HTTP_METHOD_PATCH  = 'PATCH';

  /**
   * Access token.
   *
   * @var string
   */
  protected $accessToken = NULL;

  /**
   * Authorization code.
   *
   * @var string
   */
  protected $authorizationCode = NULL;

  /**
   * Client ID.
   *
   * @var string
   */
  protected $clientID = NULL;

  /**
   * Client secret.
   *
   * @var string
   */
  protected $clientSecret = NULL;

  /**
   * A list of provider endpoints.
   *
   * @var array
   */
  protected $endpoints = array(
    'bitly' => array(
      'authorization' => 'https://bitly.com/oauth/authorize',
      'token'         => 'https://api-ssl.bitly.com/oauth/access_token',
      'user'          => 'https://api-ssl.bitly.com/v3/user/info',
    ),
    'facebook' => array(
      'authorization' => 'https://graph.facebook.com/oauth/authorize',
      'token'         => 'https://graph.facebook.com/oauth/access_token',
      'user'          => 'https://graph.facebook.com/me',
    ),
    'github' => array(
      'authorization' => 'https://github.com/login/oauth/authorize',
      'token'         => 'https://github.com/login/oauth/access_token',
      'user'          => 'https://api.github.com/user',
    ),
    'google' => array(
      'authorization' => 'https://accounts.google.com/o/oauth2/auth',
      'token'         => 'https://accounts.google.com/o/oauth2/token',
      'user'          => 'https://www.googleapis.com/oauth2/v2/userinfo',
    ),
    'wordpress' => array(
      'authorization' => 'https://public-api.wordpress.com/oauth2/authorize',
      'token'         => 'https://public-api.wordpress.com/oauth2/token',
      'user'          => 'https://public-api.wordpress.com/rest/v1/me/?pretty=1',
    ),
  );

  /**
   * Has recieved a valid access token.
   *
   * @var bool
   */
  protected $hasAccessToken = FALSE;

  /**
   * Has recieved a valid authorization code.
   *
   * @var bool
   */
  protected $hasAuthorizationCode = FALSE;

  /**
   * Shorthand name for provider to authorize with.
   *
   * @var string
   */
  protected $provider = NULL;

  /**
   * Redirect URL for the application.
   *
   * @var string
   */
  protected $redirectUri = NULL;

  /**
   * A list of permissions you wish access to from the provider.
   *
   * @var array
   */
  protected $scope = array();

  /**
   * The type of token to operate with.
   *
   * @var string
   */
  protected $tokenType = 'bearer';

  /**
   * The response from the getUserInfo() call.
   *
   * @var array
   */
  public $userInfo = array();

  /**
   * Construct.
   *
   * @param string $clientID
   *   Client ID.
   * @param string $clientSecret
   *   Client secret.
   * @param string $redirectUri
   *   Redirect Uri for the application.
   * @param string $provider
   *   The provider to authorize with.
   * @param array $endpoints
   *   (optional) A list of provider endpoints that can be used with shorthand.
   */
  public function __construct($clientID, $clientSecret, $redirectUri, $provider, array $endpoints = array()) {
    $this->clientID = $clientID;
    $this->clientSecret = $clientSecret;
    $this->redirectUri = $redirectUri;
    $this->provider = $provider;

    if (count($endpoints)) {
      foreach ($endpoints as $key => $value) {
        if (!isset($this->endpoints[$key]))
          $this->endpoints[$key] = array(
            'authorization' => '',
            'token'         => '',
            'user'          => '',
          );

        if (is_array($value) &&
            count($value)) {
          foreach ($value as $vk => $vv)
            $this->endpoints[$key][$vk] = $vv;
        }
      }
    }

    if ($this->clientID == NULL ||
        empty($this->clientID))
      throw new Exception('Client ID has not been set.');

    if ($this->clientSecret == NULL ||
        empty($this->clientSecret))
      throw new Exception('Client secret has not been set.');

    if ($this->redirectUri == NULL ||
        empty($this->redirectUri))
      throw new Exception('Redirect URL has not been set.');

    if ($this->provider == NULL ||
        empty($this->provider))
      throw new Exception('Provider has not been set.');

    if (!isset($this->endpoints[$this->provider]))
      throw new Exception('Provider endpoints has not been set.');

    if (isset($_GET['code']))
      $this->getAuthorizationCode();
  }

  /**
   * Attempt to authorize by redirecting to the provider.
   *
   * @param array $parameters
   *   (optional) Array of extra parameters, like scope or state. (Ex: array('scope' => 'email', 'state' => ''))
   */
  public function authorize(array $parameters = array()) {
    if (isset($parameters['scope']))
      $this->scope = $parameters['scope'];

    $parameters = array_merge(
      array(
        'response_type' => 'code',
        'client_id'     => $this->clientID,
        'redirect_uri'  => $this->redirectUri,
      ),
      $parameters
    );

    $authorizationURL =
      $this->endpoints[$this->provider]['authorization'] .
      '?' . http_build_query($parameters, NULL, '&');

    header('Location: ' . $authorizationURL);
    exit;
  }

  /**
   * Execute a request (using cURL).
   *
   * @param string $url
   *   Url for the request.
   * @param array $parameters
   *   A list of parameters to send along with the request.
   * @param string $httpMethod
   *   Which HTTP method to use.
   * @param array $httpHeaders
   *   A list of headers to send along with the request.
   *
   * @return array
   *   A compilation of results.
   */
  private function executeRequest($url, $parameters, $httpMethod = self::HTTP_METHOD_GET, array $httpHeaders = array()) {
    $curlOptions = array(
      CURLOPT_RETURNTRANSFER => TRUE,
      CURLOPT_SSL_VERIFYPEER => FALSE,
      CURLOPT_SSL_VERIFYHOST => 0,
      CURLOPT_CUSTOMREQUEST  => $httpMethod,
    );

    if ($httpMethod == self::HTTP_METHOD_POST) {
      $curlOptions[CURLOPT_POST]       = TRUE;
      $curlOptions[CURLOPT_POSTFIELDS] = http_build_query($parameters, NULL, '&');
    }
    else if ($httpMethod == self::HTTP_METHOD_GET)
      $url .= '?' . http_build_query($parameters, NULL, '&');

    $curlOptions[CURLOPT_URL] = $url;

    if (is_array($httpHeaders) &&
        count($httpHeaders)) {
      $headers = array();

      foreach ($httpHeaders as $key => $value)
        $headers[] = $key . ': ' . $value;

      $curlOptions[CURLOPT_HTTPHEADER] = $headers;
    }

    $curlHandle = curl_init();

    curl_setopt_array(
      $curlHandle,
      $curlOptions
    );

    $result = curl_exec($curlHandle);

    $httpCode = curl_getinfo($curlHandle, CURLINFO_HTTP_CODE);
    $contentType = curl_getinfo($curlHandle, CURLINFO_CONTENT_TYPE);
    $jsonDecoded = NULL;

    if ($curlError = curl_error($curlHandle))
      throw new Exception($curlError, Exception::CURL_ERROR);
    else
      $jsonDecoded = json_decode($result, TRUE);

    curl_close($curlHandle);

    return array(
      'result'      => ($jsonDecoded === NULL ? $result : $jsonDecoded),
      'code'        => $httpCode,
      'contentType' => $contentType,
      'url'         => $url,
    );
  }

  /**
   * Attempt to get an access token from the provider.
   *
   * @return bool
   */
  public function getAccessToken() {
    if (!$this->hasAuthorizationCode)
      throw new Exception('An autorization has not taken place yet.');

    $parameters = array(
      'client_id'     => $this->clientID,
      'client_secret' => $this->clientSecret,
      'code'          => $this->authorizationCode,
      'grant_type'    => 'authorization_code',
      'redirect_uri'  => $this->redirectUri,
      'scope'         => $this->scope,
    );

    $response = $this->executeRequest(
      $this->endpoints[$this->provider]['token'],
      $parameters,
      self::HTTP_METHOD_POST
    );

    echo '<pre>' . print_r($response, TRUE) . '</pre>';

    if (is_array($response) &&
        isset($response['code']) &&
        isset($response['result']) &&
        $response['code'] == 200) {
      if (is_string($response['result'])) {
        $parsed = NULL;

        parse_str($response['result'], $parsed);

        if (isset($parsed['access_token'])) {
          $this->accessToken = $parsed['access_token'];
          $this->hasAccessToken = TRUE;
        }

        if (isset($parsed['token_type']))
          $this->tokenType = $parsed['token_type'];
      }
      else if (is_array($response['result'])) {
        if (isset($response['result']['access_token'])) {
          $this->accessToken = $response['result']['access_token'];
          $this->hasAccessToken = TRUE;
        }

        if (isset($response['result']['token_type']))
          $this->tokenType = $response['result']['token_type'];
      }
    }

    return $this->hasAccessToken;
  }

  /**
   * Extract the authorization code from the _GET var if present.
   */
  public function getAuthorizationCode() {
    if (isset($_GET['code'])) {
      $this->authorizationCode = $_GET['code'];
      $this->hasAuthorizationCode = TRUE;
    }
  }

  /**
   * Query the provider for various information about the user.
   *
   * @return bool
   */
  public function getUserInfo() {
    if (!$this->hasAuthorizationCode)
      throw new Exception('An autorization has not taken place yet.');

    if (!$this->hasAccessToken)
      throw new Exception('Access token not present.');

    $parameters = array(
      'access_token' => $this->accessToken,
    );

    $httpHeaders = array(
      'authorization' => $this->tokenType . ' ' . $this->accessToken,
    );

    $response = $this->executeRequest(
      $this->endpoints[$this->provider]['user'],
      $parameters,
      self::HTTP_METHOD_GET,
      $httpHeaders
    );

    echo '<pre>' . print_r($response, TRUE) . '</pre>';
  }

  /**
   * Attempt to run through each step in a standard OAuth2 process.
   *
   * @param array $parameters
   *   (optional) Array of extra parameters to send along.
   *
   * @return bool
   */
  public function process(array $parameters = array()) {
    if (!$this->hasAuthorizationCode)
      $this->authorize($parameters);

    echo 'authorizationCode: ' . $this->authorizationCode . '<br />';
    echo '<strong>getAccessToken()</strong><br />';

    if ($this->hasAuthorizationCode &&
        !$this->hasAccessToken)
      $this->getAccessToken();

    echo 'accessToken: ' . $this->accessToken . '<br />';
    echo '<strong>getUserInfo()</strong><br />';

    if ($this->hasAuthorizationCode &&
        $this->hasAccessToken)
      $this->getUserInfo();

    return (count($this->userInfo) ? TRUE : FALSE);
  }
}
