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


require_relative 'helpers'
require_relative 'protocol'

module Triauth
  # Derives a domain name under which identity records are stored, and reads the identity records from DNS
  # (e.g., `john._at.triauthdemo.org` for `mode=public` domains or `_AXD3AKE8EX._at.triauthdemo.org` for `mode=private` domains).
  #
  # Objects of this class start in unresolved state, and need to be resolved with a call to resolve() that queries the DNS.
  class IdentityDomain
    # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
    attr_reader :config
    # @return [String] The identifier for which identity domain is constructed.
    attr_reader :identifier
    # The resolution options, as fixed by `set_options(...)`; `nil` until then.
    # @return [Hash, nil]
    attr_reader :options
    # The domain name the identity records are published under, derived from the identifier and the
    # resolution mode. `nil` until resolved.
    # @return [String, nil]
    attr_reader :domain_name
    # The identity records as read from the DNS, in `Triauth::Resolvers::Base#resolve_config` form.
    # `nil` until resolved.
    # @return [Array<Hash>, nil] each record `{key: String, value: String, options: Hash, ttl: (Integer, nil), dnssec: (Boolean, nil)}`
    attr_reader :identity_records
    # The lookup code that addressed the records in private mode. `nil` in every other mode.
    # @return [String, nil]
    attr_reader :lookup_code
    # The commitment a private-mode record set must carry to be accepted - the digest of the derived
    # full label. `nil` in every other mode.
    # @return [String, nil]
    attr_reader :expected_commitment
    # Whether the identity domain resolved successfully; `nil` until resolve() has run.
    # @return [Boolean, nil]
    attr_reader :resolved

    # Returns the full derived label of a private-mode identity: the base32 encoding of the HMAC-SHA-256
    # of the identifier, keyed by the identity's lookup code.
    #
    # The identifier needs to be in downcase, as results of this function are case-sensitive.
    #
    # @param identifier [String] the identifier to derive from
    # @param lookup_code [String] the identity's lookup code, the HMAC key
    # @return [String] the 52-character base32 string whose first PRIVATE_LABEL_LENGTH characters form the label of the identity domain, e.g., '4GIBDU53B3KGFSZUD5KRVUGITFQ2QAN2C55FNXO25S53WGT6CK6A'
    def self.derive_full_label(identifier, lookup_code)
      return Helpers.uint8_array_to_base32(
        Helpers.hmac_sha256(Helpers.string_to_utf8_bytes(lookup_code), Helpers.string_to_utf8_bytes(identifier))
      )
    end

    # Derives a domain name under which identity records are being kept for the passed identifier.
    # Expects a pre-validated identifier (see Triauth::Validator.validate_identifier).
    #
    # @param identifier [String] a pre-validated user identifier
    # @param options [Hash] options as read from the DNS TXT record specifying the authentication endpoint (`mode`), plus the identity's `lookupCode` under `mode=private`. Defaults to `{}`.
    # @return [Hash, nil] the domain name (`{domainName: String}`, carrying the untruncated label as `fullLabel` under `mode=private`), or nil when no domain name can be derived (an unknown mode, or a missing/malformed lookup code under `mode=private`)
    def self.derive(identifier, options = {})
      # Extract the original domain name from the identifier
      identifier_domain = identifier.split('@', -1)[1]

      # The mode decides the way identity domain is derived
      mode = options[:mode]

      if mode == 'public'
        return { domainName: identifier.sub('@', Protocol::AT_MARKER) }
      end

      if mode == 'private'
        if !Helpers.is_lookup_code(options[:lookupCode])
          return nil
        end

        # HMAC the identifier under the lookup code, base32 encode, and keep the fixed-length label
        full_label = IdentityDomain.derive_full_label(identifier, options[:lookupCode])

        return { domainName: "_#{full_label[0, Protocol::PRIVATE_LABEL_LENGTH]}#{Protocol::AT_MARKER}#{identifier_domain}", fullLabel: full_label }
      end

      # If an unknown mode is set, return `nil`
      return nil
    end

    # Constructs a new instance of IdentityDomain basing on the identifier.
    #
    # Objects of this class start in an un-resolved state, and a call to the resolve() that
    # performs the DNS resolution needs to be made before most of the other methods can be used.
    #
    # @param identifier [String] The identifier for which identity domain is constructed.
    # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
    def initialize(identifier, config = {})
      # Memoizes the resolution, so that concurrent and repeated `resolve()` calls share a single
      # DNS round trip. A rejection is memoized too, and is replayed to every later caller.
      # The memoized outcome of the first resolution: `[true, result]` or `[false, error]`, guarded by the mutex
      # (the port of the `#resolvePromise` promise).
      @resolve_mutex = Mutex.new
      @resolve_promise = nil

      @config = Helpers.merge_config(config)

      @identifier = identifier

      @options = nil

      @domain_name = nil

      @identity_records = nil

      @lookup_code = nil

      @expected_commitment = nil

      @resolved = nil
    end

    # Sets the options for future `resolve` calls.
    # May be called only once.
    #
    # @param options [Hash] Options read from the authentication endpoint DNS record (e.g., `{mode: 'public'|'private'}`), plus the identity's `lookupCode` where its mode consumes one.
    #
    # @return [IdentityDomain] this instance, so the call chains straight into resolve().
    #
    # @raise [RuntimeError] when the options have already been set.
    def set_options(options)
      if !@options.nil?
        raise 'Options of a Triauth.IdentityDomain are already set'
      end

      @options = options

      return self
    end

    # Resolves the identity domain by deriving the domain name from the identifier
    # (using the authentication endpoint options) and querying the DNS for its identity records.
    # Sets the `domain_name` and `identity_records` properties accordingly.
    #
    # Set resolution options with `set_options(...)` prior to the call.
    #
    # The result is memoized, and subsequent calls to `resolve` do not perform DNS lookups.
    # Rejections are currently memoized too.
    #
    # @return [Boolean] true when identity records have been fetched, false when the domain name could not be derived.
    #
    # @raise [RuntimeError] when the resolution options have not been set yet - call `set_options(...)` first.
    def resolve
      if @options.nil?
        raise 'Triauth.IdentityDomain options not set'
      end

      # Memoize the outcome so that multiple and/or concurrent calls return the same status.
      @resolve_mutex.synchronize do
        @resolve_promise ||= begin
          # The body of the memoized resolution is a lambda, so that every JS `return` is a `return` of the lambda.
          resolution = lambda do
            derived = IdentityDomain.derive(@identifier, @options)
            # `derived?.domainName`: a nil `derived` prints empty here, where JS prints `undefined`
            Helpers.log(@config, :debug, "Identity domain for identifier \"#{@identifier}\" is \"#{derived&.[](:domainName)}\"")

            # A derivation that cannot be performed leaves the identity without an identity domain,
            # which is like an identity that publishes no records.
            if derived.nil?
              @resolved = false
              return [true, @resolved]
            end

            domain_name, full_label = derived.values_at(:domainName, :fullLabel)

            if @options[:mode] == 'private'
              @lookup_code = @options[:lookupCode]
              @expected_commitment = Helpers.sha256(full_label)
            end

            @domain_name = domain_name
            @identity_records = @config[:resolver].resolve_config(domain_name, @config)

            @resolved = true
            return [true, @resolved]
          end
          resolution.call
        rescue StandardError => err
          Helpers.log(@config, :debug, err)

          @resolved = false
          [false, err]
        end
      end

      ok, value = @resolve_promise
      raise value if !ok

      return value
    end
  end
end
