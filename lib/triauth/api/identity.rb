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


require_relative '../config'
require_relative '../helpers'
require_relative '../error'
require_relative '../identity'
require_relative '../validator'

module Triauth
  module Api
    # Methods related to identity that are a part of the official triauth-ruby API.
    module Identity
      # The whois method can be used to check if a given personal identifier exists, and obtain public details stored in its identity records.
      # For domains operating in `mode=private`, the `lookupCode` is required to look up the identity records.
      #
      # Upon call, it returns a Hash with a `status` property of:
      # `-1` if domain does not exist or is not configured for triauth,
      # `0` if domain is configured but identifier does not exist or could not be located (e.g., a missing or wrong `lookupCode` under `mode=private`),
      # and `1` if identifier exists.
      # On error, it returns an `{error: {code, message}}` Hash instead (with no `status`).
      #
      # Synopsis:
      #
      # ```ruby
      #
      # whois_result = Triauth.whois({ identifier: identifier })
      # whois_result = Triauth.whois({ identifier: identifier, lookupCode: lookup_code }) # for an identity under a mode=private domain
      # # returns {error: {code: String, reason?: String, message: String}} upon error
      # # returns {status: 1, identifier, authenticationEndpoint: {…}, identityDomain, secure, publicProfile: {…}, groups: […], devices: […], includes: […]} if identifier exists
      # # returns {status: 0, identifier, authenticationEndpoint: {…}, identityDomain} if domain is configured for triauth but the identifier does not exist or, for mode=private domains, a missing or wrong lookupCode was supplied
      # # returns {status: -1, identifier} if domain is not configured for triauth
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.whois({ identifier: 'john@triauthdemo.org' })
      # #
      # # {
      # #   status: 1,
      # #   identifier: "john@triauthdemo.org",
      # #   authenticationEndpoint: {
      # #     url: "https://auth.triauthdemo.org/",
      # #     options: {
      # #       mode: "public",
      # #       include: "any"
      # #     },
      # #     secure: true
      # #   },
      # #   identityDomain: "john._at.triauthdemo.org",
      # #   secure: true,
      # #   publicProfile: {
      # #     initials: "JD",
      # #     name: "John Doe"
      # #   },
      # #   groups: [],
      # #   devices: [
      # #     {
      # #       deviceName: "laptop",
      # #       deviceTag: "5I4NnX-4lW3gdTqGW3zKpLsLR9oRiWip8zp6mqQgkL4",
      # #       keys: [
      # #         {
      # #           value: "BCkB_Cr-7pvY1Y2buYRksJPb09Tqld7M3SDII36cp_C7k08NPTWvbj0p14oMBGDGbGZ1qLkfnJSARBbAj1sA0fs",
      # #           options: {
      # #             type: "es256",
      # #             use: "attest,auth,ping,sign,stamp"
      # #           }
      # #         },
      # #         {
      # #           value: "BLglw14iw47KUztRHdeKNfBBBMf5P4SsZg9O9za44mO2BceHZlcQwFmtO1crjVNnwwZszqtMhErs3divGeQrQI4",
      # #           options: {
      # #             type: "es256",
      # #             use: "attest,auth,ping,sign,stamp"
      # #           }
      # #         }
      # #       ]
      # #     },
      # #     {
      # #       deviceName: "desktop",
      # #       deviceTag: "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ",
      # #       keys: [
      # #         {
      # #           value: "BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
      # #           options: {
      # #             type: "es256",
      # #             use: "attest,auth,ping,sign,stamp"
      # #           }
      # #         }
      # #       ]
      # #     }
      # #   ],
      # #   includes: []
      # # }
      # #
      # ```
      #
      # The `includes` array lists the identity's published `include` statements, e.g.:
      #
      # ```ruby
      # # includes: [
      # #   {
      # #     ref: "jane@triauthdemo.org",
      # #     options: {use: "sign", scope: "any"},
      # #     tag: "LJwdl7N9xsSO4LV6T3gmmxVk_eXLyS58jw7czzooByw"
      # #   }
      # # ]
      # ```
      #
      # @param options [Hash] whois lookup options. Defaults to nil (a missing argument is rejected with `invalid_arguments`).
      # @option options [String] :identifier the identifier to look up
      # @option options [String] :lookupCode the identity's lookup code (used when domain is in private mode)
      # @param config [Hash] optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Hash] one of the following shapes:
      #   `{error: {code: String, reason?: String, message: String}}`,
      #   `{identifier: String, status: -1}`,
      #   `{identifier: String, status: 0, authenticationEndpoint: {url: String, options: Hash, secure: Boolean}, identityDomain: (String, nil)}`, or
      #   `{identifier: String, status: 1, authenticationEndpoint: {url: String, options: Hash, secure: Boolean}, identityDomain: String, secure: Boolean, publicProfile: Hash, groups: Array<String>, devices: Array<{deviceName: String, deviceTag: String, keys: Array<{value: String, options: Hash}>}>, includes: Array<{ref: String, options: Hash, tag: String}>}`
      #   - `{error: {code, message}}` — the arguments were rejected (`invalid_arguments` for a missing `identifier` or an unrecognized option key — a bare identifier string or a config Hash in the options position included, `invalid_config` for an unrecognized config key, `invalid_lookup_code` for a malformed `lookupCode`, `invalid_identifier` for an invalid identifier) or the DNS resolution failed (`dns_unavailable`).
      #   - `{identifier, status: -1}` — the identity domain does not exist or is not configured for triauth (no `authenticationEndpoint` could be resolved).
      #   - `{identifier, status: 0, authenticationEndpoint, identityDomain}` — the domain is triauth-configured but no identity records exist for this identifier. Under `mode=private` this is also the answer when the call carries no `lookupCode` (then `identityDomain` is `nil`, as no identity domain could be derived) or a wrong one (a malformed `lookupCode` is instead rejected with the error `invalid_lookup_code`).
      #   - `{identifier, status: 1, authenticationEndpoint, identityDomain, secure, publicProfile, groups, devices, includes}` — the identifier was fully resolved. The `secure` flag is resolution-level: true only when DNSSEC was reported for the domain's `triauth` configuration record and for every well-formed record of the identity answer (DNSSEC validates answers, not individual records, so one flag describes the identity answer; `authenticationEndpoint.secure` isolates the endpoint record's own status). The `groups` array lists the identity's fully-qualified group-membership claims (sorted, deduplicated; e.g., `['admins@triauthdemo.org']`). Each entry in `devices` carries:
      #     - `deviceName` `{String}` — a user given name of the device,
      #     - `deviceTag` `{String}` — a unique tag identifying the device by its associated public keys,
      #     - `keys` `{Array<{value, options}>}` — the device's individual published keys.
      #
      #     Each entry in `includes` (ordered by `tag`) carries:
      #     - `ref` `{String}` — the delegate the grant covers, as published (lowercased): either an identifier (`jane@example.com`) or an identity domain (`jane._at.example.com`),
      #     - `options` `{Hash}` — the grant's options: `use` lists the flows the grant covers (all five when unpublished) and `scope` the service hosts it works at (`any` = every host, or a comma-separated host list),
      #     - `tag` `{String}` — the grant digest that appears as the first segment of a delegated result's composite `deviceTag`.
      def self.whois(options = nil, config = {})
        config = Helpers.merge_config(config)
        config[:logger] = (config[:logger].respond_to?(:spawn) ? config[:logger].spawn(config[:cid]) : nil) || config[:logger]

        Helpers.log(config, :info, 'Processing Triauth.whois')
        ts = Helpers.now

        begin
          # Ensure only recognized options are present to help avoid misspellings
          if !Helpers.has_only_known_properties(options, %i[identifier lookupCode])
            raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Unrecognized function argument' })
          end

          # Reject config carrying unknown keys
          if !Helpers.has_only_known_properties(config, Triauth::KNOWN_CONFIG_KEYS)
            raise Triauth::Error.new({ code: 'invalid_config', message: 'Unrecognized configuration key' })
          end

          identifier = options[:identifier]
          lookup_code = options[:lookupCode]

          if !Helpers.is_string(identifier)
            raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Invalid or missing function arguments' })
          end

          # A malformed lookup code is a caller error, never repaired, and rejected before any DNS lookup
          # (`lookupCode !== undefined` is "member absent": an explicit `lookupCode: nil` is validated and rejected with `invalid_lookup_code`, the JS `null` outcome)
          if options.key?(:lookupCode)
            validation_result = Validator.validate_lookup_code(lookup_code)
            if !validation_result[:valid]
              raise Triauth::Error.new(validation_result[:errors][0])
            end
          end

          retval = { status: nil, identifier: identifier }

          # (`Triauth::Identity`, qualified: the bare `Identity` is this module. `{lookupCode}` is passed even when absent:
          # `{ lookupCode: nil }` reaches `IdentityDomain#set_options`, whose `is_lookup_code(nil)` is false exactly as `isLookupCode(undefined)` is)
          identity = Triauth::Identity.new(identifier, { lookupCode: lookup_code }, config)

          if !identity.authentication_endpoint.resolve
            # `Object.assign(retval, {...})` mutates and returns `retval`: so does `Hash#merge!` (`Helpers.object_assign` would return a new Hash)
            return Helpers.clone(retval.merge!({ status: -1 }))
          end

          retval.merge!(
            {
              authenticationEndpoint: {
                url: identity.authentication_endpoint.url_for(nil),
                options: identity.authentication_endpoint.options,
                secure: identity.authentication_endpoint.secure == true
              }
            }
          )

          if !identity.resolve
            return Helpers.clone(retval.merge!({ status: 0, identityDomain: identity.identity_domain.domain_name }))
          end

          devices = []
          # `for...in` over the key-group object: `Helpers.ordered_entries` yields the JS object key order (`key_groups` is keyed by device-name Symbols)
          Helpers.ordered_entries(identity.keys.key_groups).each do |device_name, key_group|
            if key_group[:valid]
              # only expose white-listed properties
              keys = key_group[:keys].map { |key| { value: key[:value], options: key[:options] } }

              devices.push({ deviceName: device_name.to_s, deviceTag: key_group[:tag], keys: keys }) # the device name as a String, as `for...in` yields it
            end
          end

          # only expose white-listed properties of the include statements (grants) admitted under the domain's include policy
          includes = identity.includes.list.map { |incl| { ref: incl[:ref], options: incl[:options], tag: incl[:tag] } }

          return Helpers.clone(
            retval.merge!(
              {
                status: 1,

                identityDomain: identity.identity_domain.domain_name,
                secure: identity.secure,

                publicProfile: identity.public_profile,
                groups: identity.groups,

                devices: devices,
                includes: includes
              }
            )
          )
        rescue StandardError => err
          return Triauth::Error.process(err, config)
        ensure
          Helpers.log(config, :info, "Completed in #{(Helpers.now - ts).round}ms")
        end
      end
    end
  end
end
