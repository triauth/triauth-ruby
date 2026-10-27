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


require_relative 'base'
require_relative 'registry'
require_relative '../helpers'

module Triauth
  module Verifiers
    # A verifier for Ed25519 (EdDSA over Curve25519) signatures.
    #
    # Support for Ed25519 keys in triauth is considered experimental: it needs the openssl gem 3.x over
    # OpenSSL 1.1.1 or later (the Ruby 3.2 default gem over a current OpenSSL library has it).
    class Ed25519 < Base
      # @return [OpenSSL::PKey::PKey] The public key the signatures are verified against.
      attr_reader :public_key
      # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
      attr_reader :config

      # Constructs a new instance of Ed25519 verifier for the given public crypto key and options.
      #
      # @param public_key [OpenSSL::PKey::PKey] A public key in form of an `OpenSSL::PKey` object.
      # @param options [Hash] Key options as read from the DNS record that contained the public_key. Defaults to `{}`.
      # @param context [Hash] Per-verification context. Unused by this verifier. Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      def initialize(public_key, options = {}, context = {}, config = {}) # rubocop:disable Lint/UnusedMethodArgument -- `options` and `context` are the verifier constructor contract, unused here as in triauth-js
        super()

        @public_key = public_key
        @config = Helpers.merge_config(config)
      end

      # Builds an instance of the Verifier from the raw key information read from the DNS.
      #
      # @param raw_public_key [String] A key as published in the DNS record (base64url of the 32-byte raw public key).
      # @param options [Hash] Key options as read from the DNS record that contained the raw_public_key. Defaults to `{}`.
      # @param context [Hash] Per-verification context. Unused by this verifier. Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Ed25519, nil] The instance of this verifier, or nil if key is invalid or other problem occurred.
      def self.from_publishable_key(raw_public_key, options = {}, context = {}, config = {})
        config = Helpers.merge_config(config)

        begin
          public_key = Base.import_key(Helpers.base64url_to_uint8(raw_public_key), { name: 'Ed25519' })
          return new(public_key, options, context, config)
        rescue StandardError => err
          Helpers.log(config, :debug, err)
          return nil
        end
      end

      # Verifies that a given signature matches the verifier's public key and the given message.
      #
      # @param message [String] The message to verify against.
      # @param signature_base64url [String] Base64Url encoded signature.
      # @param signed_data [Hash] Signature envelope's signedMetadata. Unused by this verifier.
      # @param unsigned_data [Hash] Signature envelope's unsignedMetadata. Unused by this verifier.
      #
      # @return [Boolean] true or false basing on the verification result.
      def verify(message, signature_base64url, signed_data, unsigned_data) # rubocop:disable Lint/UnusedMethodArgument -- `signed_data` and `unsigned_data` are the verifier contract, unused here as in triauth-js
        data = Helpers.string_to_utf8_bytes(message)
        signature = Helpers.base64url_to_uint8(signature_base64url)
        return Base.verify_signature({ name: 'Ed25519' }, @public_key, signature, data)
      rescue StandardError => err
        Helpers.log(@config, :debug, err)
        return false
      end
    end

    Triauth::Verifiers.register('ed25519', Ed25519)
  end
end
