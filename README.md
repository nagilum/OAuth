# OAuth v1 and v2 libs for PHP.

I wrote this wrapper framework to make the login part of my other projects to a
minimum. Less code, me happy.

## Example of usage

### OAuth1

### OAuth2

```php
require_once 'OAuth2.php';

$client = new OAuth2\Client(
  'your-apps-client-id',
  'your-apps-client-secret',
  'shorthand-provider-name',
  'callback-uri-for-client'
  );

if (!$client->is_authorized)
  $client->authorize();
```

When you create a new instance of the class it will run through and try to
retrieve an access token and user information if the authorization code has
been provided.

When you call the `authorize()` function, you will be redirected to the
provider's login page. If you're already logged in, you might just get
automatically redirected back to the callback URI.

Google requires that the callback URI is your-domain.com/oauth2callback, so you
might as well use that for all providers.

When you have gained full authorization, the general user information will be
stored in the `$client->user_info` and your private unique ID from the provider
will be stored in `$client->unique_id`.

## Providers

Currently available providers in this library are:

### Oauth1

### OAuth2

[Bitly](http://dev.bitly.com/authentication.html),
[Facebook](https://developers.facebook.com/docs/),
[GitHub](http://developer.github.com/v3/),
[Google](http://code.google.com/more/),
[Live](http://msdn.microsoft.com/en-us/library/hh243647.aspx),
[Wordpress](http://developer.wordpress.com/docs/api/).

## License

These libraries are released under the MIT license.

Copyright (c) 2013 Stian Hanger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
