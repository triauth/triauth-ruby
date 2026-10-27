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


require_relative '../error'
require_relative '../helpers'

module Triauth
  module Resolvers
    # A base class from which other DNS resolvers inherit common functions.
    # Subclasses are expected to implement `resolve(domain_name, type, options = {}, config = {})`.
    class Base
      # Queries the DNS for resource records of a given type that are stored under a given domain name.
      #
      # This is the abstract contract that concrete subclasses (e.g., DnsJson, SystemDns, MultiResolver) implement.
      #
      # @param domain_name [String] A domain name to query the DNS for.
      # @param type [String] A type of DNS resource record to look for (e.g., 'TXT', 'A').
      # @param options [Hash] Per-call overrides for the resolver options passed to the constructor. Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Array<Hash>] The array of retrieved DNS resource records in `{value, ttl, dnssec}` format
      #   (`value` a String, `ttl` an Integer or nil, `dnssec` a Boolean or nil).
      #
      # @raise [RuntimeError] always - this method is abstract and carries no implementation of its own.
      def resolve(domain_name, type, options = {}, config = {}) # rubocop:disable Lint/UnusedMethodArgument -- the abstract signature is the contract
        raise 'Triauth.Resolvers.Base#resolve is abstract and must be implemented by a subclass'
      end

      # Returns configuration entries that are stored as DNS TXT records under a given domain name.
      # Each configuration entry consist of a key, optional value, and any number of options.
      #
      # Options are the maximal trailing run of whole whitespace-separated `key=value` tokens;
      # the text before that run is the entry's value, kept verbatim — `=`-containing text outside
      # the trailing run is ordinary value text and needs no escaping. Option values and the value
      # are percent-decoded; a record violating these rules is ignored as a whole.
      #
      # @example
      #
      #   # Given the following DNS TXT record of an example.com domain:
      #   # `example.com IN TXT "app triauth-authenticator style=dark logo=none"`
      #   resolve_config('example.com')
      #   => [{key: "app", value: "triauth-authenticator", options: {style: "dark", logo: "none"}, ttl: 60, dnssec: false}]
      #
      # @param domain_name [String] a domain name for/of which configuration should be read from the DNS
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Array<Hash>] The array of configuration entries/objects, as read from DNS, each in form of
      #   `{key, value, options, ttl, dnssec}` (`key` and `value` Strings, `options` a Hash of Symbol keys to String
      #   values, `ttl` an Integer or nil, `dnssec` a Boolean or nil).
      #
      # @raise [Triauth::Error] `dns_unavailable` when the underlying DNS query fails - intentionally propagated so that
      #   API methods report a retryable error instead of treating the name as unconfigured.
      def resolve_config(domain_name, config = {})
        config = Helpers.merge_config(config)

        Helpers.log(config, :debug, "[DNS] Querying DNS for config records of #{domain_name}")

        rv = []

        begin
          txt_records = resolve(domain_name, 'TXT', {}, config)
        rescue StandardError => err
          Helpers.log(config, :debug, "DNS name resolution failed for #{domain_name}", { cause: err })
          raise Triauth::Error.new({ code: 'dns_unavailable', message: 'DNS resolution failed, try again later' })
        end

        # A record is its key, a blank run, and a rest with no line terminator. An option is a whole
        # whitespace-separated key=value token, so `a+b=c` never yields one. The `\S` stops the blank
        # run and the rest from trading characters, so the parse stays linear in the record size.
        record_regexp = /\A([A-Za-z0-9_-]+)#{Helpers::JS_WS}+(#{Helpers::JS_NOT_WS}#{Helpers::JS_DOT}*)\z/
        option_token_regexp = /\A([A-Za-z0-9_\-\[\].@]+)=(#{Helpers::JS_NOT_WS}+)\z/

        # The callback is a lambda, so that `return` leaves the record as in JS, from inside the option loop too (where it
        # is spelled `return nil`, so the iterator lint sees it is deliberate); the block's `rescue` is the `try`/`catch`.
        txt_records.each(&lambda do |record|
          if (md = record[:value].match(record_regexp))
            entry = { key: md[1], value: '', options: {}, ttl: record[:ttl], dnssec: record[:dnssec] }

            if !Helpers.is_normal_string(entry[:key], 255)
              return
            end

            # Split once, keeping the blank runs (odd indexes) so the value is reassembled verbatim.
            # The option run is the maximal suffix of option tokens, collected right-to-left.
            parts = Helpers.trim_end(md[2]).split(/(#{Helpers::JS_WS}+)/, -1)
            option_matches = []
            i = parts.length - 1
            while i >= 0 && (option_md = parts[i].match(option_token_regexp))
              option_matches.push(option_md)
              i -= 2
            end
            entry[:value] = i < 0 ? '' : parts[0..i].join
            option_matches.reverse!

            # Process the run left to right; a repeated option key takes its last occurrence.
            # Option values are consumed as published - no percent-decoding at this layer: options are
            # machine vocabularies (and enter tag preimages), so their bytes stay those of the zone file.
            option_matches.each do |m|
              option_key = m[1]
              option_value = m[2]

              if !(Helpers.is_normal_string(option_key, 255) && Helpers.is_normal_string(option_value, nil))
                return nil
              end

              # The map has no prototype, so a name such as `__proto__` is an ordinary key here, and the rules of
              # each record family judge it like any other unknown option
              entry[:options][option_key.to_sym] = option_value
            end

            # The text before the option run is the value. An options-only record has none and is ignored below.
            entry[:value] = Helpers.trim(entry[:value])

            if !Helpers.is_normal_string(entry[:value], nil)
              return
            end

            return rv.push(entry)
          end
        rescue StandardError => err
          Helpers.log(config, :debug, err)
          # continue regardless of error
        end)

        Helpers.log(config, :debug, "[DNS] Parsed #{rv.length} DNS config record(s) from #{domain_name}")

        return rv
      end
    end
  end
end
