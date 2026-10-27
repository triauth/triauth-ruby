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
  # Holds information about authentication endpoint for a given domain.
  #
  # Authentication endpoint is the URL under which Triauth Authenticator application, for the given identifier and its domain,
  # is available and can be communicated with.
  #
  # Objects of this class start in unresolved state, and need to be resolved with a call to resolve() that queries the DNS.
  class AuthenticationEndpoint
    # The option keys the `triauth` record defines. The endpoint keeps these and the `x-` extensions and ignores
    # every other option of the record, so a record that spells a future option still configures a verifier that
    # predates it, and no other published name reaches a result.
    ENDPOINT_OPTIONS = %i[mode include].freeze
    private_constant :ENDPOINT_OPTIONS

    # @return [String] The domain name for which authentication endpoint shall be resolved.
    attr_reader :domain_name
    # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
    attr_reader :config
    # The endpoint's lowercase host — the value of the domain's `triauth` DNS record.
    # `nil` until resolved.
    # @return [String, nil]
    attr_reader :host
    # The `mode` and `include` options as read from the `triauth` DNS record, with the defaults filled in when
    # absent, and its `x-` extension options as published. Every other option of the record is ignored.
    # Empty until resolved.
    # @return [Hash{Symbol => Object}]
    attr_reader :options
    # Whether the DNS record defining this authentication endpoint was protected by DNSSEC.
    # `true` only when the resolver reported a validated (AD) response for the matched `triauth` record;
    # `false` when it was not validated or the resolver did not report DNSSEC status;
    # `nil` until resolved.
    # @return [Boolean, nil]
    attr_reader :secure
    # Expiry of the resolved `triauth` record: the resolution time plus its TTL, in milliseconds;
    # `nil` when the record carried no TTL. Every expiry reported for an identity is bounded by it.
    # @return [Integer, nil]
    attr_reader :expires
    # @return [Boolean, nil] Whether the authentication endpoint resolved successfully; `nil` until resolve() has run.
    attr_reader :resolved

    # Constructs a new instance of AuthenticationEndpoint basing on the domain name extracted form the identifier.
    #
    # Objects of this class start in an un-resolved state, and a call to the resolve() that
    # performs the DNS resolution needs to be made before most of the other methods can be used.
    #
    # @param domain_name [String] The domain name for which authentication endpoint shall be resolved.
    # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
    def initialize(domain_name, config = {})
      # Memoizes the resolution, so that concurrent and repeated `resolve()` calls share a single
      # DNS round trip. A rejection is memoized too, and is replayed to every later caller.
      # The memoized outcome of the first resolution: `[true, result]` or `[false, error]`, guarded by the mutex
      # (the port of the `#resolvePromise` promise).
      @resolve_mutex = Mutex.new
      @resolve_promise = nil

      @domain_name = domain_name
      @config = Helpers.merge_config(config)

      @host = nil

      @options = {}

      @secure = nil

      @expires = nil

      @resolved = nil
    end

    # Keeps the options the `triauth` record defines, `mode` and `include`, and its `x-` extensions, and
    # leaves every other option of the record out.
    #
    # @param options [Hash{Symbol => Object}] The options of the record, as parsed.
    #
    # @return [Hash{Symbol => Object}] the kept options, in a fresh Hash (the JS map without a prototype).
    def self.known_options(options)
      known = {}

      options.each do |key, value|
        if ENDPOINT_OPTIONS.include?(key) || (key[0] == 'x' && key[1] == '-')
          known[key] = value
        end
      end

      return known
    end

    # Returns the URL of the authentication endpoint, with the passed action and parameters included.
    #
    # With an action, it is the final URL to which the user's web browser should be redirected in the challenge-response flow.
    # The params are passed inside the URL fragment identifier for privacy reasons.
    #
    # @param action [String, nil] An action verb used to construct the URL - e.g., 'auth', 'sign', etc., or nil for the bare endpoint URL.
    # @param params [Hash] Parameters that should be included in the URL, ignored when action is nil (and then omitted: defaults to nil).
    #
    # @return [String] an url of authentication endpoint with the given action and parameters.
    #
    # @raise [RuntimeError] when the endpoint has not been resolved yet - call `resolve()` first.
    def url_for(action, params = nil)
      if !@resolved
        raise 'Unresolved AuthenticationEndpoint'
      end

      if action.nil?
        return "https://#{@host}/"
      end

      # Parameter values are base64url by the time they get here
      pairs = params.map { |key, value| "#{key}=#{value}" }

      return "https://#{@host}/#{action}.html#?#{pairs.join('&')}"
    end

    # Resolves the authentication endpoint for the domain by querying the DNS,
    # and sets the `host`, `options`, and `secure` properties accordingly basing on the DNS response.
    #
    # The result is memoized, and subsequent calls to `resolve` do not perform DNS lookups.
    # Rejections are currently memoized too.
    #
    # @return [Boolean] true if the URL of authentication endpoint has been resolved, false otherwise.
    def resolve
      # Memoize the outcome so that multiple and/or concurrent calls return the same status.
      @resolve_mutex.synchronize do
        @resolve_promise ||= begin
          # The body of the memoized resolution is a lambda, so that every JS `return` is a `return` of the lambda.
          resolution = lambda do
            Helpers.log(@config, :debug, "Resolving Triauth.AuthenticationEndpoint for domain #{@domain_name}")

            domain_config = @config[:resolver].resolve_config(@domain_name, @config)

            domain_config.each do |entry|
              if entry[:key] == 'triauth' && Helpers.is_domain_name(entry[:value])
                if !@host.nil? && !@host.empty?
                  # Multiple triauth records published — refuse to choose
                  Helpers.log(@config, :warn, 'Multiple triauth records found; refusing to choose', { domainName: @domain_name })
                  @host = nil
                  @options = {}
                  @secure = nil
                  @expires = nil
                  break
                end

                @host = entry[:value].downcase
                @options = AuthenticationEndpoint.known_options(entry[:options])
                @secure = entry[:dnssec] == true
                @expires = Helpers.is_integer(entry[:ttl]) ? Helpers.date_now + (entry[:ttl] * 1000) : nil

                # Set defaults
                @options[:mode] = Protocol::DEFAULT_MODE if @options[:mode].nil?
                @options[:include] = Protocol::DEFAULT_INCLUDE if @options[:include].nil?
              end
            end

            Helpers.log(@config, :debug, "Triauth.AuthenticationEndpoint for domain #{@domain_name} is #{@host}")

            @resolved = !@host.nil? && !@host.empty?
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
