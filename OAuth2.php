<?php

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

class Client {
  protected $authorizationCode = NULL;
  protected $clientID          = NULL;
  protected $clientSecret      = NULL;
  protected $provider          = NULL;
  protected $redirectUri       = NULL;

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

  public function __construct($clientID, $clientSecret, $provider, $redirectUri = NULL, $refreshToken = NULL) {
    $this->clientID = $clientID;
    $this->clientSecret = $clientSecret;
    $this->provider = $provider;
    $this->redirectUri = $redirectUri;
    $this->refreshToken = $refreshToken;

    if ($this->redirectUri == NULL ||
        empty($this->redirectUri))
      $this->redirectUri =
      'http' .
      (isset($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) == 'on' ? 's' : '') .
      '://' .
      $_SERVER['HTTP_HOST'] .
      '/';

    $this->handlePageRequest();
  }

  public function __get($name) {
    if (isset($this->public[$name]))
      return $this->public[$name];

    return FALSE;
  }

  public function authorize($scope = NULL) {
    $parameters = array(
      'client_id'     => $this->clientID,
      'display'       => 'page',
      'locale'        => 'en',
      'redirect_uri'  => $this->redirectUri,
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

  protected function debug($var, $func = NULL) {
    if ($func !== NULL)
      echo '<strong>' . $func . '()</strong><br />';

    foreach ($GLOBALS as $tmp_varname => $tmp_value) {
      if ($tmp_value == $var) {
        echo '<strong>$' . $tmp_varname . '</strong><br />';
        break;
      }
    }

    echo '<pre>' . (is_bool($var) ? ($var === TRUE ? 'TRUE' : 'FALSE') : print_r($var, TRUE)) . '</pre>';
  }

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

  protected function handleTokenResponse($token, $error = NULL) {
    if (!empty($token)) {
      $this->public[ACCESS_TOKEN]     = $token[ACCESS_TOKEN];
      $this->public[HAS_ACCESS_TOKEN] = TRUE;
      $this->public[REFRESH_TOKEN]    = (isset($token[REFRESH_TOKEN]) ? $token[REFRESH_TOKEN] : NULL);
      $this->public[TOKEN_TYPE]       = (isset($token[TOKEN_TYPE]) ? $token[TOKEN_TYPE] : 'Bearer');
    }
  }

  protected function handleUserInformation($response) {
    $userInfo = (array) json_decode($response);

    if (empty($userInfo))
      $userInfo = $this->parseQueryString($response);

    $this->public[HAS_USER_INFO] = TRUE;
    $this->public[USER_INFO]     = $userInfo;

    if (isset($userInfo['id']))
      $this->public[UNIQUE_ID] = $userInfo['id'];
  }

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

  protected function requestAccessTokenByRefreshToken($refreshToken) {
    return $this->requestAccessToken(
      array(
        'client_id'     => $this->clientID,
        'redirect_uri'  => $this->redirectUri,
        'client_secret' => $this->clientSecret,
        'refresh_token' => $refreshToken,
        'grant_type'    => REFRESH_TOKEN,
        )
      );
  }

  protected function requestAccessTokenByVerifier($verifier) {
    return $this->requestAccessToken(
      array(
        'client_id'     => $this->clientID,
        'redirect_uri'  => $this->redirectUri,
        'client_secret' => $this->clientSecret,
        'code'          => $verifier,
        'grant_type'    => AUTHENTICATION_CODE
        )
      );
  }

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
