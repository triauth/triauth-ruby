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


require 'json'
require_relative 'helpers'
require_relative 'identity'
require_relative 'protocol'

module Triauth
  # Represents an authentication request (challenge) that is sent from client application to the Triauth Authenticator.
  class Challenge
    # @return [Triauth::Identity] The Identity the challenge is addressed to.
    attr_reader :identity
    # @return [Hash{Symbol => Object}] The challenge's wire fields - `type`, `identifier`, `nonce`, `iat` and `ver`, plus any per-flow additions.
    attr_reader :data
    # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
    attr_reader :config
    # Populated by Challenge.from_string when re-hydrating a serialized challenge; left nil
    # for freshly built challenges (use to_s to serialize on demand).
    # @return [String, nil]
    attr_accessor :challenge_string

    # Recreates the Challenge from the given challenge.
    #
    # @param challenge_string [String] a challenge as sent to the authenticator: the part of the challenge stored during
    #                                  stage 1 of the challenge-response flow before its `.` and decryption key.
    # @param config [Hash] optional overrides for the global Triauth.config settings. Defaults to `{}`.
    #
    # @return [Triauth::Challenge]
    # @raise [StandardError] upon problems with deserialization of the challenge or the format of personal identifier encoded within
    def self.from_string(challenge_string, config = {})
      decoded_challenge = Helpers.base64url_to_string(challenge_string)
      challenge_data = Helpers.safe_parse_json(decoded_challenge)
      identity = Identity.new(challenge_data[:identifier], {}, config)

      retval = Challenge.new(identity, challenge_data, config)
      retval.challenge_string = challenge_string

      return retval
    end

    # Builds a new Challenge and populates the required request data fields with the default values,
    # unless a value for them was provided through the data argument.
    #
    # @param type [String] the type of request associated with this challenge, e.g., 'auth', 'sign', etc.
    # @param identity [Triauth::Identity] identity for which the authentication request is being built.
    # @param data [Hash] data to include in the authentication request, may override the defaults
    # @param config [Hash] optional overrides for the global Triauth.config settings. Defaults to `{}`.
    #
    # @return [Triauth::Challenge]
    def self.build(type, identity, data, config = {})
      config = Helpers.merge_config(config)

      # Populate the data fields that must be present in the triauth authentication request with default values
      data = Helpers.object_assign(
        {},
        data,
        {
          type: type,
          identifier: identity.identifier, # the Identifier the request is addressed to
          nonce: Helpers.random_string(24, config), # cryptographic nonce
          iat: Helpers.date_now, # timestamp of when authentication request was created
          ver: Protocol::VERSION
        }
      )

      return Challenge.new(identity, data, config)
    end

    # Constructs a new instance of Challenge for the given identity and challenge data.
    #
    # Use the `build` factory to mint a fresh challenge, or `from_string` to re-hydrate a serialized
    # one; this constructor stores what it is given and validates nothing on its own.
    #
    # @param identity [Triauth::Identity] The Identity the challenge is addressed to.
    # @param data [Hash] The challenge's wire fields - `type`, `identifier`, `nonce`, `iat` and
    #   `ver`, plus any per-flow additions such as `msg`, `attest` or `attachments`. Defaults to `{}`.
    # @param config [Hash] optional overrides for the global Triauth.config settings. Defaults to `{}`.
    def initialize(identity, data = {}, config = {})
      @identity = identity
      @data = data
      @config = Helpers.merge_config(config)

      # Populated by Challenge.from_string when re-hydrating a serialized challenge; left nil
      # for freshly built challenges (use to_s to serialize on demand).
      @challenge_string = nil
    end

    # Serializes this authentication request into a string that may be used as a challenge.
    #
    # The port of `toString()`.
    #
    # @return [String] a challenge which can be included in the redirect URL
    def to_s
      challenge_json = JSON.generate(@data)
      return Helpers.string_to_base64url(challenge_json)
    end
  end
end
