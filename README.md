OAuth v1 and v2 libs for PHP.

I wrote this wrapper to make the login part of my other projects to a minimum.
Less code, me happy.

### Example of the simplest usage

```php
require_once 'OAuth.php';
OAuthProcess('your-client-id', 'your-client-secret', 'your-app-redirect-url', 'provider-to-use');
```

Current supported providers are:
[Bitly](#),
[Facebook](#),
[GitHub](#),
[Google](#),
[Wordpress](#).
