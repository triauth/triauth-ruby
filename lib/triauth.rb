# frozen_string_literal: true

# Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0


require_relative 'triauth/version'
require_relative 'triauth/protocol'
require_relative 'triauth/config'
require_relative 'triauth/error'
require_relative 'triauth/logger'
require_relative 'triauth/helpers'
require_relative 'triauth/verifiers'
require_relative 'triauth/resolvers'
require_relative 'triauth/validator'
require_relative 'triauth/authentication_endpoint'
require_relative 'triauth/identity_domain'
require_relative 'triauth/identity_keys'
require_relative 'triauth/identity_includes'
require_relative 'triauth/identity'
require_relative 'triauth/signature'
require_relative 'triauth/multi_signature'
require_relative 'triauth/challenge'
require_relative 'triauth/response'
require_relative 'triauth/response_cipher'
require_relative 'triauth/request_cipher'
require_relative 'triauth/challenge_response_flow'
require_relative 'triauth/api'

# Entry point of triauth-ruby, assembling the `Triauth` namespace.
#
# Example use:
#
# ```ruby
# require 'triauth'
# Triauth.authenticate(...)
# ```
module Triauth
  # Top-level classes and namespaces
  # (the `export` lines have no counterpart: `Helpers`, `Logger`, `Validator`, `Error`, `Identity`, `IdentityKeys`,
  # `IdentityIncludes`, `IdentityDomain`, `AuthenticationEndpoint`, `Challenge`, `Response`, `Signature`, `MultiSignature`,
  # `ChallengeResponseFlow`, `Triauth.config`, `Resolvers`, `Verifiers` and `Api` are defined on this module by the files required above)

  # `index.js` re-exports `LIMITS` of `protocol.js` at the top level; so does the port.
  LIMITS = Protocol::LIMITS

  # Top-level API method aliases
  class << self
    # (see ::Triauth::Api::Authentication.authenticate)
    # (`options = {}`: a missing argument is the JS `undefined`, which `ChallengeResponseFlow.perform`'s own default turns into `{}` (`invalid_arguments` from the stage detection); an explicit nil is the JS `null` (`invalid_arguments` from the known-keys guard))
    def authenticate(options = {}, config = {}) = Api::Authentication.authenticate(options, config)

    # (see ::Triauth::Api::Authentication.check)
    def check(options = nil, config = {}) = Api::Authentication.check(options, config)

    # (see ::Triauth::Api::Authentication.ping)
    # (`options = {}`: as for `authenticate`)
    def ping(options = {}, config = {}) = Api::Authentication.ping(options, config)

    # (see ::Triauth::Api::Attestation.attest)
    def attest(options = nil, config = {}) = Api::Attestation.attest(options, config)

    # (see ::Triauth::Api::Identity.whois)
    def whois(options = nil, config = {}) = Api::Identity.whois(options, config)

    # (see ::Triauth::Api::Validation.validate)
    def validate(objects = nil, config = {}) = Api::Validation.validate(objects, config)

    # (see ::Triauth::Api::Signing.sign)
    def sign(options = nil, config = {}) = Api::Signing.sign(options, config)

    # (see ::Triauth::Api::Signing.stamp)
    def stamp(options = nil, config = {}) = Api::Signing.stamp(options, config)

    # (see ::Triauth::Api::Signing.verify)
    def verify(message = nil, signature = nil, constraints = {}, config = {}) = Api::Signing.verify(message, signature, constraints, config)
  end

  # Initialize defaults that depend on constructed instances

  # `config.logger ??= ...`: assign only when nullish
  config[:logger] = Logger.new(Logger::CONSOLE, { logLevel: 'error', prefix: '[triauth]' }) if config[:logger].nil?

  # `config.resolver ??= ...`: assign only when nullish (`4e3` and `8.5e3` are these Integers; `NodeDns` is `SystemDns`)
  if config[:resolver].nil?
    config[:resolver] = Resolvers::MultiResolver.new(
      [
        Resolvers::Cloudflare.new({ retries: 1, timeout: 4000 }),
        Resolvers::Google.new({ retries: 1, timeout: 4000 }),
        Resolvers::SystemDns.new({ timeout: 4000 })
      ],
      { maxFailures: 1, timeout: 8500 }
    )
  end

  # Web browser specific - dispatch a `triauth:ready` event when loaded
  # (dropped: the `typeof window` browser lane has no counterpart in a server-side Ruby gem)
end
