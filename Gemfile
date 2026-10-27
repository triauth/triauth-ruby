# frozen_string_literal: true

source 'https://rubygems.org'

gemspec

group :development, :test do
  gem 'minitest', '~> 5.16'
  gem 'rake', '~> 13.0'
  gem 'rubocop', '~> 1.91'
  gem 'simplecov', '~> 1.2'
  gem 'yard', '~> 0.9.45'
end

# The README Synopsis example app under examples/; not needed to test or build the gem.
group :examples, optional: true do
  gem 'puma'
  gem 'rackup'
  gem 'sinatra', '~> 4.2'
end
