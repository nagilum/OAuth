# OAuth v1 and v2 libs for PHP.

I wrote this wrapper framework to make the login part of my other projects to a minimum.
Less code, me happy.

### Example of the simplest usage

```php
require_once 'OAuth.php';
OAuthProcess(
  'your-client-id',
  'your-client-secret',
  'provider-to-use',
  'your-app-redirect-url'
);
```

This little function determines wether you want a OAuth v1 or v2 provider and connects, authorizes, validates, and get's user info. Nifty :)

If you omit the redirect-url parameter, the function will try to put it together itself from the `$_SERVER` variable.

You can initiate the OAuth v1 class yourself by using the following code.
This is what the `OAuthProcess()` function does for you based on the provider you specify.

```php
require_once 'OAuth1.php';
$client = new OAuth1\Client(
  'your-client-id',
  'your-client-secret',
  'provider-to-use',
  'your-app-redirect-url'
);
$client->process();
```

And of course the same with v2.

```php
require_once 'OAuth2.php';
$client = new OAuth2\Client(
  'your-client-id',
  'your-client-secret',
  'provider-to-use',
  'your-app-redirect-url'
);
$client->process();
```

The `process()` function for each class, as well as the `OAuthProcess()` function, takes an extra parameter array if you wish to add scope or the like.

```php
$client->process(
  array(
    'scope' => 'email'
  )
);
```

or

```php
OAuthProcess(
  'your-client-id',
  'your-client-secret',
  'provider-to-use',
  null,
  array(
    'scope' => 'email'
  )
);
```

## Providers

Current supported providers are:
[Bitly](http://dev.bitly.com/authentication.html),
[Facebook](https://developers.facebook.com/docs/),
[GitHub](http://developer.github.com/v3/),
[Google](http://code.google.com/more/),
[Wordpress](http://developer.wordpress.com/docs/api/).

## Disclaimer

This code is provided as-is, meaning I really don't give a hoot what you do with it.
But don't come complaining to me if you bring down upon yourself the wrath of NSA with your filthy missuse.
