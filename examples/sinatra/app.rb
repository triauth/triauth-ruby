# frozen_string_literal: true

require 'triauth'

require 'sinatra'
require 'securerandom'

enable :sessions
set :session_secret, SecureRandom.hex(64) # replace with your own secret

get '/' do
  if session[:identifier]
    return "Logged in as #{session[:identifier]}"
  end

  error_message = session[:error] ? session[:error][:message] : ''
  session[:error] = nil

  <<~HTML
    <form action="/login" method="post">
        <input type="text" name="identifier" placeholder="Enter your identifier">
        <span style="color:red;">#{error_message}</span>
        <input type="submit" value="Sign in with triauth">
    </form>
  HTML
end

post '/login' do
  # Start a sign-in only from this site's own pages, so that another site cannot sign the user in as an attacker
  if request.env['HTTP_SEC_FETCH_SITE'] && request.env['HTTP_SEC_FETCH_SITE'] != 'same-origin'
    halt 403
  end

  identifier = params[:identifier]

  # Demo only: in production replace with your own static URL
  # Do not trust request.host_with_port unless it is validated by your reverse proxy/framework config.
  callback_url = "#{request.scheme}://#{request.host_with_port}/callback"

  auth_result = Triauth.authenticate({
    identifier: identifier,
    callbackUrl: callback_url,
    ext: { callbackMethod: 'GET' } # a GET callback brings the session cookie back with it
  })

  if auth_result[:challenge] && auth_result[:redirectUrl]
    session[:challenge] = auth_result[:challenge]
    redirect auth_result[:redirectUrl], 302
  else
    session[:error] = auth_result[:error]
    redirect '/', 302
  end
end

get '/callback' do
  challenge = session[:challenge]
  response = params[:response]

  session.delete(:challenge)

  auth_result = Triauth.authenticate({
    challenge: challenge,
    response: response
  })

  if auth_result[:authenticated]
    session[:identifier] = auth_result[:identifier]
  else
    session[:error] = auth_result[:error]
  end

  redirect '/', 302 # always redirect, so that the response does not stay in the address bar
end

set :port, 3000 # `ruby app.rb` serves on port 3000; `rackup -p 3000` serves through config.ru
