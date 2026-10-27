# frozen_string_literal: true

require_relative 'setup'
require_relative 'internals/test_resolvers'
require_relative 'internals/test_resolvers_zone'
require_relative 'internals/test_verifiers'
require_relative 'internals/test_caching_resolver'
require_relative 'internals/test_logger'
require_relative 'internals/test_helpers'
require_relative 'internals/test_canonical_url'
require_relative 'internals/test_validator' # port-only
require_relative 'internals/test_config'
require_relative 'internals/test_protocol'
require_relative 'internals/test_identity_keys'
require_relative 'internals/test_identity_includes'
require_relative 'internals/test_identity_domain'
require_relative 'internals/test_authentication_endpoint'
require_relative 'internals/test_signature'
require_relative 'internals/test_challenge_response_flow' # port-only
require_relative 'internals/test_response_cipher'
require_relative 'internals/test_request_cipher'

# Wrapping the calls under a single 'Internals' label
describe 'Internals' do
  TestInternals.resolvers
  TestInternals.resolvers_zone
  TestInternals.verifiers
  TestInternals.caching_resolver
  TestInternals.identity_keys
  TestInternals.identity_includes
  TestInternals.logger
  TestInternals.helpers
  TestInternals.canonical_url
  TestInternals.validator # port-only
  TestInternals.signature
  TestInternals.challenge_response_flow # port-only
  TestInternals.identity_domain
  TestInternals.authentication_endpoint
  TestInternals.config
  TestInternals.protocol
  TestInternals.response_cipher
  TestInternals.request_cipher
end
