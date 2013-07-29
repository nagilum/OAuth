OAuth v1 and v2 libs for PHP.

I wrote this wrapper to make the login part of my other projects to a minimum.
Less code, me happy.

### Example of the simplest usage

```php
require_once 'OAuth.php';
OAuthProcess('your-client-id', 'your-client-secret', 'provider-to-use', 'your-app-redirect-url');
```

This little function determines wether you want a OAuth v1 or v2 provider and connects, authorizes, validates, and get's user info. Nifty :)

If you omit the redirect-url parameter, the function will try to put it together itself.

Current supported providers are:
[Bitly](http://dev.bitly.com/authentication.html),
[Facebook](https://developers.facebook.com/docs/),
[GitHub](http://developer.github.com/v3/),
[Google](http://code.google.com/more/),
[Wordpress](http://developer.wordpress.com/docs/api/).
