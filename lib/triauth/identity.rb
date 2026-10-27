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


require_relative 'error'
require_relative 'validator'
require_relative 'authentication_endpoint'
require_relative 'identity_domain'
require_relative 'identity_keys'
require_relative 'protocol'
require_relative 'helpers'
require_relative 'identity_includes'

module Triauth
  # Represents an entity that is identified by the provided `identifier`.
  #
  # Objects of this class start in unresolved state, and need to be resolved with a call to resolve() that queries the DNS.
  class Identity
    # A regexp for the reserved keywords that may appear in the identity records (DNS TXT records)
    # and are recognized and returned as a part of publicProfile.
    PUBLIC_PROFILE_KEYWORDS = /\A(name|initials)\z/
    private_constant :PUBLIC_PROFILE_KEYWORDS

    # @return [String] Identifier (e.g., `john@triauthdemo.org`) for which the Identity object is constructed.
    attr_reader :identifier
    # @return [Hash] Resolution options (`lookupCode`: the lookup code that addresses the identity records - required in private mode).
    attr_reader :options
    # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
    attr_reader :config
    # The public profile entries published in the identity records (e.g., `name`, `initials`, and
    # any `x-` prefixed key); a nil value marks a key that is published but carries no value.
    # Populated by resolve().
    # @return [Hash{Symbol => String, nil}]
    attr_reader :public_profile
    # Fully-qualified group names this identity claims membership in (e.g., ['admins@triauthdemo.org']);
    # deduplicated and sorted, populated by resolve()
    # @return [Array<String>]
    attr_reader :groups
    # @return [String] The domain name of the identifier.
    attr_reader :domain_name
    # @return [Triauth::AuthenticationEndpoint] The authentication endpoint of the identifier's domain. Resolved by resolve().
    attr_reader :authentication_endpoint
    # @return [Triauth::IdentityDomain] The identity domain of the identifier. Resolved by resolve().
    attr_reader :identity_domain
    # The public keys published for this identity, grouped by device. Populated by resolve().
    # @return [Triauth::IdentityKeys]
    attr_reader :keys
    # The delegation grants published for this identity. Populated by resolve().
    # @return [Triauth::IdentityIncludes]
    attr_reader :includes
    # Whether the identity resolved successfully; `nil` until resolve() has run.
    # @return [Boolean, nil]
    attr_reader :resolved
    # Whether the whole identity resolution - the endpoint record and every identity record - was
    # DNSSEC-validated; computed by resolve().
    # @return [Boolean]
    attr_reader :secure

    # Constructs a new instance of Identity for the given identifier.
    #
    # Objects of this class start in an un-resolved state, and a call to the resolve() method that
    # performs the DNS resolution needs to be made before most of the other methods can be used.
    #
    # @param identifier [String] Identifier (e.g., `john@triauthdemo.org`) for which the Identity object is constructed.
    # @param options [Hash] Resolution options. Defaults to `{}`.
    # @option options [String] :lookupCode The lookup code that addresses the identity records - required in private mode.
    # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
    #
    # @raise [Triauth::Error] carrying the first validation error when the identifier is malformed.
    def initialize(identifier, options = {}, config = {})
      # Memoizes the resolution, so that concurrent and repeated `resolve()` calls share a single
      # DNS round trip. A rejection is memoized too, and is replayed to every later caller.
      # The memoized outcome of the first resolution: `[true, result]` or `[false, error]`, guarded by the mutex
      # (the port of the `#resolvePromise` promise).
      @resolve_mutex = Mutex.new
      @resolve_promise = nil

      @identifier = identifier
      @options = options
      @config = Helpers.merge_config(config)

      # Ensure received identifier is valid
      validation_result = Validator.validate_identifier(@identifier)
      if !validation_result[:valid]
        raise Triauth::Error.new(validation_result[:errors][0])
      end

      @public_profile = {}

      @groups = []

      @domain_name = @identifier.split('@', -1)[1]

      @authentication_endpoint = AuthenticationEndpoint.new(@domain_name, @config)
      @identity_domain = IdentityDomain.new(@identifier, @config)

      @keys = IdentityKeys.new(@config)

      @includes = IdentityIncludes.new(@config)

      @resolved = nil

      @secure = false
    end

    # Resolves the identity by querying the DNS.
    # Identities must have at least one identity record present to be successfully resolved.
    #
    # The result is memoized, and subsequent calls to the `resolve` function do not perform DNS lookups.
    # Rejections are currently memoized too.
    #
    # @return [Boolean] true if the identity has been resolved, false otherwise.
    def resolve
      # Memoize the outcome so that multiple and/or concurrent calls return the same status.
      @resolve_mutex.synchronize do
        @resolve_promise ||= begin
          # The body of the memoized resolution is a lambda, so that every JS `return` is a `return` of the lambda.
          resolution = lambda do
            Helpers.log(@config, :debug, "Resolving Triauth.Identity for identifier #{@identifier}")

            # Resolve the authenticationEndpoint to read triauth configuration, and then the identityDomain
            #
            # This will query the DNS for TXT records stored under the domain name of the identifier, looking for a TXT record starting with 'triauth' keyword.
            # We start with this, to make sure domain is configured for triauth, and to get the mode in which identity domains should be derived from identifiers (e.g., public or private).
            #
            # Next, resolve the identity domain, using the options as read from the DNS TXT record defining the authentication endpoint, to obtain its identityRecords.
            # This will query the DNS for TXT records stored at the domain name that is derived from the user's identifier (e.g., 'john._at.triauthdemo.org' (public mode), or '_4GIBDU53B3._at.private.triauthdemo.org' (private mode)).
            if !@authentication_endpoint.resolve ||
               !@identity_domain.set_options({ mode: @authentication_endpoint.options[:mode], lookupCode: @options[:lookupCode] }).resolve
              @resolved = false
              return [true, @resolved]
            end

            identity_records = @identity_domain.identity_records

            # The endpoint record is a dependency of key discovery (its options select the identity domain
            # the keys are read from), so keys can only be as secure as the endpoint record itself.
            endpoint_secure = @authentication_endpoint.secure == true
            include_policy = IdentityIncludes.parse_policy(@authentication_endpoint.options[:include])

            public_profile_extension_count = 0
            public_profile = {} # local copy, until object is resolved
            groups = Set.new # local set of bare group names; qualified and assigned once resolved
            identity_secure = endpoint_secure # identity can be only as secure as the endpoint answer
            commitment = nil # the `commit` record value, if present

            identity_records.each do |entry|
              identity_secure &&= entry[:dnssec] == true

              # DNS-derived freshness of this record: fresh until its TTL runs out
              expires = (Helpers.is_integer(entry[:ttl]) ? Helpers.date_now + (entry[:ttl] * 1000) : nil)

              # Profile values are the only record values that are percent-decoded
              profile_value = PUBLIC_PROFILE_KEYWORDS.match?(entry[:key]) || entry[:key].start_with?('x-') ? Helpers.percent_decode(entry[:value]) : nil

              # `key` record - add to this.keys (IdentityKeys)
              if entry[:key] == 'key'
                @keys.add(entry[:value], entry[:options], { expires: expires })

              # `include` record - add to this.includes (IdentityIncludes)
              elsif entry[:key] == 'include'
                @includes.add(entry[:value], entry[:options], { expires: expires, includePolicy: include_policy, localDomainName: @domain_name })

              # `groups` record - a comma-separated list of group names this identity claims membership in, later scoped to the identifier's domain
              elsif entry[:key] == 'groups' && groups.size < Protocol::LIMITS[:maxGroups]

                # No critical options are defined, so any critical option means the record is ignored ('x-' options are inert)
                if !Helpers.verify_options_schema(entry[:options], {})
                  Helpers.log(@config, :debug, 'Ignoring groups record due to unrecognized options', { identifier: @identifier })
                  next
                end

                # Group names follow the device-name grammar; a record with any malformed name is ignored as a whole, never repaired.
                names = Helpers.ascii_lowercase(entry[:value]).split(',', -1)
                if !names.all? { |name| Validator.validate_group_name(name)[:valid] }
                  Helpers.log(@config, :debug, 'Ignoring groups record with a malformed group name', { identifier: @identifier })
                  next
                end

                names.each do |name|
                  next if groups.include?(name) # duplicates never consume the cap

                  if groups.size >= Protocol::LIMITS[:maxGroups]
                    Helpers.log(@config, :debug, 'Ignoring groups and further group records over the limit', { limit: Protocol::LIMITS[:maxGroups] })
                    break
                  end
                  groups.add(name)
                end

              # `commit` record - the commitment binding these records to the identity's derivation (its lookup code)
              elsif entry[:key] == 'commit'

                # No critical options are defined; the value is a 43-character base64url digest
                if commitment.nil? &&
                   Helpers.verify_options_schema(entry[:options], {}) &&
                   Helpers.is_base64url_string(entry[:value])
                  commitment = entry[:value]

                else
                  commitment = false
                  Helpers.log(@config, :debug, 'Ignoring malformed or duplicated commit record(s)', { identifier: @identifier })

                end

              # publicProfile record - value is exposed raw, so it's the responsibility of API callers to escape it before rendering
              # (the publicProfile keys are Symbols, the profile's key rule)
              elsif PUBLIC_PROFILE_KEYWORDS.match?(entry[:key]) &&
                    !profile_value.nil? &&
                    Helpers.is_normal_string(profile_value, Protocol::LIMITS[:publicProfileMaxValueBytesize])

                # Do not allow doubled keywords - drop the whole entry from publicProfile
                if public_profile.key?(entry[:key].to_sym)
                  public_profile[entry[:key].to_sym] = nil
                  Helpers.log(@config, :debug, 'Ignoring doubled publicProfile entry', { keyword: entry[:key], identifier: @identifier })
                  next
                end

                public_profile[entry[:key].to_sym] = profile_value

              # Public profile extension / experimental keyword(s) in `x-` namespace
              # - 'x-' namespace is open-ended, with a cap on the number of distinct extensions kept
              # - similar as with recognized publicProfile entries - keys and values exposed raw, so must be escaped by callers before rendering
              elsif entry[:key].start_with?('x-') &&
                    Helpers.is_normal_string(entry[:key], Protocol::LIMITS[:publicProfileMaxKeyBytesize]) &&
                    !profile_value.nil? &&
                    Helpers.is_normal_string(profile_value, Protocol::LIMITS[:publicProfileMaxValueBytesize])

                # Do not allow doubled keywords - drop the whole entry from publicProfile
                if public_profile.key?(entry[:key].to_sym)
                  public_profile[entry[:key].to_sym] = nil
                  Helpers.log(@config, :debug, 'Ignoring doubled publicProfile entry', { keyword: entry[:key], identifier: @identifier })
                  next
                end

                if public_profile_extension_count < Protocol::LIMITS[:publicProfileMaxExtensions]
                  public_profile[entry[:key].to_sym] = profile_value
                  public_profile_extension_count += 1

                else
                  Helpers.log(@config, :debug, 'Ignoring publicProfile extension over the limit', { keyword: entry[:key], identifier: @identifier })
                end

              else
                Helpers.log(@config, :debug, 'Ignoring unrecognized identity record', { keyword: entry[:key], identifier: @identifier, domainName: @identity_domain.domain_name })

              end
            end

            # When 'private' mode is set for the domain, identityRecords must carry a valid/matching 'commit ...' entry, for the identity to be resolved.
            # The value of `commit ...` entry is supposed to be base64url(SHA-256(<untruncated base32 label>))
            if !@identity_domain.expected_commitment.nil? &&
               commitment != @identity_domain.expected_commitment
              Helpers.log(@config, :info, 'Commit record missing, mismatched, or duplicated - identity unresolved', { identifier: @identifier })
              @resolved = false
              return [true, @resolved]
            end

            # Remove 'nil' records from local publicProfile and assign to this.publicProfile
            @public_profile = public_profile.compact # `Object.fromEntries(Object.entries(publicProfile).filter(([, v]) => v !== null))`

            # Sorted (DNS answer order is not stable) and qualified with the identifier's domain
            @groups = groups.to_a.sort.map { |name| "#{name}@#{@domain_name}" }

            @secure = identity_secure

            Helpers.log(@config, :debug, "Parsed identity records for #{@identifier} - #{@keys.count} devices, #{@public_profile.size} profile entries, #{@groups.length} groups")

            @resolved = identity_records.length > 0
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
