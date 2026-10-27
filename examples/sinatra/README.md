# Sign in with triauth - Sinatra example

The complete example of the [Synopsis](../../README.md#synopsis): a three-route [Sinatra](https://sinatrarb.com/)
application (`/`, `/login`, `/callback`) that signs a user in with triauth and keeps the
challenge and the signed-in identifier in the session.

```shell
bundle install
bundle exec rackup -p 3000
```

Then open <http://localhost:3000/> and enter an identifier (e.g., `john@triauthdemo.org`).

The callback URL is derived from the request's `Host` header for the demo only; in production use
your own static URL, as the comment in `app.rb` says.
