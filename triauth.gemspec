# frozen_string_literal: true

require_relative 'lib/triauth/version'

Gem::Specification.new do |spec|
  spec.name = 'triauth'
  spec.version = Triauth::VERSION
  spec.authors = ['The Triauth Authors']
  spec.email = ['security@triauth.org']
  spec.summary = 'Authentication for modern web - a client library for the triauth protocol.'
  spec.description = 'Authentication for modern web - a client library for the triauth protocol. triauth-ruby is a faithful port of triauth-js, the reference implementation, and shares its JSON conformance suites.'
  spec.homepage = 'https://www.triauth.org/'
  spec.license = 'Apache-2.0'
  spec.required_ruby_version = '>= 3.2'

  spec.metadata = {
    'homepage_uri' => spec.homepage,
    'source_code_uri' => 'https://github.com/triauth/triauth-ruby',
    'changelog_uri' => 'https://github.com/triauth/triauth-ruby/blob/main/CHANGELOG.md',
    'bug_tracker_uri' => 'https://github.com/triauth/triauth-ruby/issues',
    'documentation_uri' => 'https://rubydoc.info/gems/triauth',
    'rubygems_mfa_required' => 'true'
  }

  # The library files plus the documents that exist at build time.
  spec.files = (Dir['lib/**/*.rb'] + %w[README.md PORTING.md LICENSE CHANGELOG.md SECURITY.md]).select { |f| File.exist?(f) }
  spec.require_paths = ['lib']
end
