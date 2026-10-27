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
require_relative '../error'
require_relative '../helpers'
require_relative '../validator'
require_relative '../identity'
require_relative '../challenge_response_flow'

module Triauth
  module Api
    # Methods related to authentication that are a part of the official triauth-ruby API.
    module Authentication
      # The authenticate method performs a challenge-response authentication based on the triauth protocol.
      # Successful authentication confirms that the user is in control of the provided identifier, and may be e.g., logged in to your website with it.
      #
      # The authentication is based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
      #
      # **1. Request**
      #
      # At first, you need to call the `Triauth.authenticate` method with the `identifier` option set to the user provided personal identifier (lowercase string),
      # a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
      # and an optional `ext` option (Hash) listing the [protocol extensions](#protocol-extensions) that you wish to use.
      #
      # In return, you will receive a Hash with the `challenge` (string) and `redirectUrl` (string).
      # You should temporarily store the `challenge` under the user's session, where the user can't tamper with it, and redirect the user's web browser to the `redirectUrl`.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # result = Triauth.authenticate({ identifier: identifier, callbackUrl: callback_url, ext: ext }) # ext is optional
      # # returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
      # # returns {error:{code, message}} when the input is invalid, DNS resolution fails, or the domain is not configured for triauth
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.authenticate(
      #   {
      #     identifier: 'john@triauthdemo.org',
      #     callbackUrl: 'https://example.com/triauth-callback'
      #   }
      # )
      # # {
      # #   challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJhdXRoIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJTSWRJaXZRRTVJbkhHQmFUWGhDb0UxMG8iLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MSwiZWsiOiJCQXZJbDlWVDJ3Z3JoS2FBMmw3MTFhWmIxSVJlWURkX0UtdVRfcDl2VnNzZndqWG5VWjVNcVhjRTNmSUNCRlpmOElFeXJoUXVmX0F0ODlSaHBZMFlScUUifQ.-rkB18wDNcYxPU7jK3Lb8nwmQcV-fhJ-1nLCxdDgEzE',
      # #   redirectUrl: 'https://auth.triauthdemo.org/auth.html#?challenge=eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJhdXRoIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJTSWRJaXZRRTVJbkhHQmFUWGhDb0UxMG8iLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MSwiZWsiOiJCQXZJbDlWVDJ3Z3JoS2FBMmw3MTFhWmIxSVJlWURkX0UtdVRfcDl2VnNzZndqWG5VWjVNcVhjRTNmSUNCRlpmOElFeXJoUXVmX0F0ODlSaHBZMFlScUUifQ'
      # # }
      # ```
      #
      # **2. Redirect**
      #
      # Once the user's web browser is redirected to the `redirectUrl`, they will be taken to the Triauth Authenticator web application, where they can approve or reject the authentication request.
      #
      # If the user approves the authentication request, Triauth Authenticator signs the challenge using one or more private keys that are available to it, and for which matching public keys may be obtained from the identity records, associated with the user's `identifier`, stored in the DNS.
      # It then redirects the web browser to the `callbackUrl`, by default using a `HTTP GET` method, and passes the signature, together with optional additional data, inside the `response` URL parameter.
      #
      # If the user declines the authentication request, the Triauth Authenticator sends `false` as the `response`, which `Triauth.authenticate` reports as the error `request_denied`.
      #
      # **3. Verify**
      #
      # After the user approves the authentication request, Triauth Authenticator redirects the web browser to the previously provided `callbackUrl`, by default through the [HTTP GET method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/GET), and passes a response in the `response` URL parameter.
      # The callback method that is used to pass the response to the client application can be configured with [callbackMethod extension](#protocol-extensions).
      #
      # Once you extract the `response` (string), you should pass it to the `Triauth.authenticate` function together with the previously stored `challenge` (string) to obtain authentication result.
      # If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`. Every other option belongs to stage 1 and is rejected here with `invalid_arguments`.
      #
      # > [!WARNING]
      # > **Invalidate the challenge after every authentication attempt.**
      # > Upon authentication attempt, remove, invalidate, or forget the associated `challenge` that was stored in the user's session or your local database,
      # > so that it cannot be re-used in replay attacks.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # authentication_result = Triauth.authenticate({ challenge: challenge, response: response })
      # # returns {authenticated:true, issuedAt, signedAt, verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, publicProfile, groups, keys, deviceName, deviceTag, sessionKey, ext} upon successful authentication
      # # returns {error:{code, message}} upon failed authentication
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.authenticate(
      #   {
      #     challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJhdXRoIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJTSWRJaXZRRTVJbkhHQmFUWGhDb0UxMG8iLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MSwiZWsiOiJCQXZJbDlWVDJ3Z3JoS2FBMmw3MTFhWmIxSVJlWURkX0UtdVRfcDl2VnNzZndqWG5VWjVNcVhjRTNmSUNCRlpmOElFeXJoUXVmX0F0ODlSaHBZMFlScUUifQ.-rkB18wDNcYxPU7jK3Lb8nwmQcV-fhJ-1nLCxdDgEzE',
      #     response: 'BNh1cQjNAGfM2AT7Kee_wcSpCMPmf393GaP5h1bOOFgrH58q9CIgGz0ChLLBzLGOUGbZB46FIgY8CPljfgKTNj4.DJguMmSAhafOTygveRsBQlHfpOcc4haXughtMSANoZO3ra2IIpYviH6H4ErvaqeRb_bEBu2e0URsJUjsA4iJ1Fu_2MMnn80zA-slH6XIsReM6i7m7a74iU_hmDmUMaL6KkwDM_LVJQw71pR1qnSLEE9EWOHHe8sqOT8t42S4TX0fhmzZFrlPm969B2eopvMFvJ0HMQ0I1USB6XB-lT0arzJt9UQB6XKsi2Dm'
      #   }
      # )
      # #
      # # {
      # #   authenticated: true,
      # #   issuedAt: 1787224748449,
      # #   signedAt: 1787224766683,
      # #   verifiedAt: 1787224766784,
      # #   expires: 1787226566784,
      # #   secure: true,
      # #   identifier: "john@triauthdemo.org",
      # #   identityDomain: "john._at.triauthdemo.org",
      # #   lookupCode: "",
      # #   actor: "",
      # #   actorIdentityDomain: "",
      # #   actorLookupCode: "",
      # #   publicProfile: {
      # #     initials: "JD",
      # #     name: "John Doe"
      # #   },
      # #   groups: [],
      # #   deviceName: "desktop",
      # #   deviceTag: "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ",
      # #   keys: [
      # #     {
      # #       value: "BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
      # #       options: {
      # #         type: "es256",
      # #         use: "attest,auth,ping,sign,stamp"
      # #       },
      # #       verified: true,
      # #       skipped: false
      # #     }
      # #   ],
      # #   sessionKey: "59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8",
      # #   ext: {}
      # # }
      # #
      # ```
      #
      # > [!IMPORTANT]
      # > Upon successful authentication, the authentication result Hash will have the `authenticated` property set to `true`, and the authenticated personal identifier available in the `identifier` property.
      # >
      # > Upon failed authentication, the `authenticated` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
      #
      # @see https://github.com/triauth/triauth-ruby#user-content-triauth-authenticate Documentation and usage examples on GitHub
      #
      # @param options [Hash] authentication options. Defaults to `{}` (a missing argument is rejected with `invalid_arguments` by the flow's stage detection, as the JS `undefined` is through `perform`'s own `options = {}` default; an explicit nil is the JS `null`, rejected with `invalid_arguments` by the known-keys guard).
      #
      # @option options [String] :identifier the user provided identifier that is being authenticated (stage 1)
      # @option options [String] :callbackUrl an application provided URL to which the user's web browser should be redirected with the response (stage 1)
      # @option options [Hash] :ext an optional Hash of protocol extensions to use (e.g., `{permissions:{ping:true}}`) (stage 1)
      #
      # @option options [String] :challenge a challenge as it was returned by the method after stage 1 call (stage 3)
      # @option options [String] :response a received response, by default delivered as a `response` URL parameter of a GET to the `callbackUrl` (overridable via the `callbackMethod` extension) (stage 3)
      #
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Hash] one of the following:
      #   `{challenge: String, redirectUrl: String}`,
      #   `{authenticated: true, issuedAt: Integer, signedAt: Integer, verifiedAt: Integer, expires: (Integer, nil), secure: Boolean, identifier: String, identityDomain: String, lookupCode: String, actor: String, actorIdentityDomain: String, actorLookupCode: String, publicProfile: Hash, groups: Array<String>, deviceName: String, deviceTag: String, keys: Array<Hash>, sessionKey: String, ext: Hash}`, or
      #   `{error: {code: String, reason?: String, message: String}}`
      #   - `{challenge: String, redirectUrl: String}`: Returned during stage 1 when a challenge is generated. The `challenge` should be stored and the user should be redirected to the `redirectUrl`.
      #   - `{authenticated: true, issuedAt: Integer, signedAt: Integer, verifiedAt: Integer, expires?: Integer, secure: Boolean, identifier: String, identityDomain: String, lookupCode: String, actor: String, actorIdentityDomain: String, actorLookupCode: String, publicProfile: Hash, groups: Array<String>, deviceName: String, deviceTag: String, keys: Array<Hash>, sessionKey: String, ext: Hash}`: Returned during stage 3 upon successful authentication. Includes:
      #     - `authenticated` (true): Indicates authentication was successful.
      #     - `issuedAt` (Integer): Unix timestamp on **your** server's clock at which you issued the challenge in stage 1 — the start of the flow's timeline.
      #     - `signedAt` (Integer): Unix timestamp on the **user's device** clock at which the authenticator signed the response. Verified to fall within the freshness window, but device-asserted — do not treat it as a trusted wall clock; prefer `issuedAt`/`verifiedAt` for authoritative timing.
      #     - `verifiedAt` (Integer): Unix timestamp on **your** server's clock at which this library confirmed the signature — the authoritative "when did this happen" anchor.
      #     - `expires` (Integer, optional): Unix timestamp at which the DNS records backing the verified keys expire (the earliest TTL expiry) and re-verification via `Triauth.check`/`Triauth.ping` is due. This is **not** a hard session lifetime: it is a hint for when to re-check, not a license to keep a session open without re-checking — a long DNS TTL otherwise delays the effect of a key revocation by the full TTL. May be `nil` when DNS records carry no TTL; in that case apply your own minimum/maximum re-check interval. Do not perform arithmetic against it without first handling the `nil` case.
      #     - `secure` (Boolean): Indicates whether DNSSEC was used for strong cryptographic integrity. `true` only when the domain's `triauth` configuration record and every well-formed record of the identity answer (for delegated authentication, of both the subject's and the delegate's answers) were DNSSEC-validated; a single non-validated identity record degrades it.
      #     - `identifier` (String): The authenticated user's identifier.
      #     - `identityDomain` (String): The domain name under which identity records are stored for this identifier (the subject's, for delegated authentication).
      #     - `lookupCode` (String): The lookup code the identifier's domain derivation consumed (under `mode=private` the identity records live at a code-derived label); `''` where none was. The same semi-secret that suffixes the `deviceTag` - handle it identically; it feeds `Triauth.whois({identifier, lookupCode})`.
      #     - `actor` (String): For delegated authentication (an `include` identity record granting a delegate the right to act on behalf of the identifier), the identifier of the delegate that actually performed the authentication; `''` for direct authentication (the user's own keys).
      #     - `actorIdentityDomain` (String): For delegated authentication, the domain name under which the delegate's identity records are stored — the records the signing keys were read from; `''` for direct authentication.
      #     - `actorLookupCode` (String): The lookup code the delegate's domain derivation consumed; `''` where none was, and always `''` for direct authentication.
      #     - `publicProfile` (Hash): Public details of the authenticated identity as read from identity records (e.g., 'name' and/or 'initials').
      #     - `groups` (Array): Fully-qualified group names the identity's records claim membership in (e.g., `['admins@triauthdemo.org']`), sorted and deduplicated; `[]` when none are published. The claim is made by the identity's DNS zone — treat it as authoritative only where that zone's operator is the authorization authority, compare entries only against other group names (never against identifiers), and escape before rendering. For delegated authentication these are the subject's groups, never the delegate's.
      #     - `deviceName` (String): User-given, public name of the device that was used for authentication, as read from the DNS key records (e.g., `"mylaptop"`).
      #     - `deviceTag` (String): Unique identifier of the device (and, for delegated authentication, the delegation) used; under `mode=private` it also carries the lookup code. Store it verbatim and pass it to `Triauth.check`.
      #     - `keys` (Array): Public keys that were considered and/or used during verification.
      #     - `sessionKey` (String): A secret of this sign-in, in 43 base64url characters, that only your application and the user's authenticator know. Pass it to `Triauth.ping`, `Triauth.sign`, `Triauth.stamp` and `Triauth.attest`. Store it with the user's server-side or encrypted session, and keep it out of logs. After a delegated sign-in, it starts with the actor's domain and a colon.
      #     - `ext` (Hash): Data returned by the authenticator application for the requested protocol extensions. Always present - `{}` when no extension data was returned (a malformed `ext` is discarded with a logged warning and also yields `{}`).
      #   - `{error: {code: String, reason?: String, message: String}}`: Returned during stage 1 or stage 3 when authentication fails, includes an error Hash with code and message.
      def self.authenticate(options = {}, config = {})
        # (`options = {}`: a missing argument is the JS `undefined`, which the flow's `perform(type, options = {}, ...)` default turns into `{}` (`invalid_arguments` from the stage detection);
        # a Ruby default applies only at the method called without the argument, so it lives here too, and an explicit nil stays the JS `null` (`invalid_arguments` from the known-keys guard))
        config = Helpers.merge_config(config)
        config[:logger] = (config[:logger].respond_to?(:spawn) ? config[:logger].spawn(config[:cid]) : nil) || config[:logger]

        # No challenge processing needed here
        # (`async () => {}` ignores its argument; a zero-parameter lambda would raise ArgumentError when the flow calls it with the `{challenge}` Hash)
        on_challenge = ->(_args) {}

        on_response = lambda do |args|
          challenge = args[:challenge]
          response = args[:response]
          session_key = args[:sessionKey]

          # Verify the response against the challenge
          result = ChallengeResponseFlow.verify_challenge_response('auth', challenge.challenge_string, challenge, response, config[:authTimeout], config)

          # Propagate the failure signals unchanged: null -> request_expired, false -> verification_failed.
          return result if !result

          sig = result[:sig]
          verify_result = result[:verifyResult]

          Helpers.log(config, :info, 'Verification successful', { identifier: sig[:identifier], deviceTag: sig[:deviceTag] })

          received_ext = sig[:signedMetadata].nil? ? nil : sig[:signedMetadata][:ext]
          # `receivedExt && ...`: `ext` is a parsed JSON value, so the JS falsy cases are nil, false, 0 and ''
          received_ext_truthy = !(received_ext.nil? || received_ext == false || received_ext == 0 || received_ext == '')
          received_ext_valid = received_ext_truthy && Validator.validate_ext(received_ext)[:errors].length == 0

          # Auxiliary data tolerance: a malformed `ext` does NOT block authentication (a buggy or
          # forward-incompatible authenticator must not lock the user out). Coerce to {} silently
          # for the caller, but log a warning so operators that care can plug a custom logger.
          if received_ext_truthy && !received_ext_valid
            Helpers.log(config, :warn, 'Discarding malformed signedMetadata.ext', { identifier: sig[:identifier], deviceTag: sig[:deviceTag] })
          end

          # (an `expires` of nil stays a present nil member: the JS result carries `expires: undefined` under structuredClone, and the JSON runner drops nil members before comparing)
          return Helpers.clone(
            {
              authenticated: true,
              issuedAt: challenge.data[:iat],
              signedAt: sig[:signedAt],
              verifiedAt: verify_result[:verifiedAt],
              expires: verify_result[:expires],
              secure: verify_result[:secure],
              identifier: sig[:identifier],
              identityDomain: sig[:identityDomain],
              lookupCode: sig[:lookupCode],
              actor: sig[:actor],
              actorIdentityDomain: sig[:actorIdentityDomain],
              actorLookupCode: sig[:actorLookupCode],
              publicProfile: sig[:publicProfile],
              groups: sig[:groups],
              deviceName: sig[:deviceName],
              deviceTag: sig[:deviceTag],
              keys: sig[:keys],
              sessionKey: sig[:actor] != '' ? "#{sig[:actor].split('@', -1)[1]}:#{session_key}" : session_key, # A delegated session is at the authenticator of the actor's domain, so its key starts with that domain (`sig.actor ?`: the actor is '' or an identifier, so the empty string is the only falsy value)
              ext: received_ext_valid ? received_ext : {}
            }
          )
        end

        return ChallengeResponseFlow.perform('auth', options, { onChallenge: on_challenge, onResponse: on_response }, config)
      end

      # The check method verifies that the user's public keys and delegation associated with the given `deviceTag` are still present and unchanged in the Domain Name System (DNS), and that the user may remain authenticated.
      # It also returns the user's current group memberships, allowing the application to detect membership changes.
      #
      # A key may be removed from the DNS by the user or their organization when, for example, an associated device is stolen, decommissioned, or the user leaves the organization.
      # Similarly, a delegation may be revoked when the user no longer allows a particular actor to act on their behalf.
      # Group membership changes may affect the user's access to your application features or resources.
      #
      # This method may be periodically called with the `identifier` and `deviceTag` as returned by the `Triauth.authenticate` method.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # check_result = Triauth.check({ identifier: identifier, deviceTag: device_tag })
      # # returns {valid:true, secure, expires, groups} keys are still present in the DNS; `expires` (when a number) is the unix timestamp until which the check method need not be called again; `expires` may be nil when DNS records carry no TTL - in that case apply your own minimum re-check interval; `groups` is the identity's current membership list - replace any session-cached groups with it on every check
      # # returns {valid:false, reason} when the device may no longer remain authenticated and should be logged out; reason is 'revoked' (the device's keys are no longer published) or 'unresolved' (the identity itself no longer resolves)
      # # returns {error} when status cannot be determined at the moment due to some error
      #
      # ```
      #
      # > [!IMPORTANT]
      # > Accept only when `valid == true` (the device keys are still present). The `reason` on a `{valid:false}` result is diagnostic only - both `'revoked'` and `'unresolved'` mean the user should be logged out.
      #
      # Example:
      #
      # ```ruby
      # Triauth.check(
      #   {
      #     identifier: "john@triauthdemo.org",
      #     deviceTag: "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ"
      #   }
      # )
      # #
      # # {
      # #   valid: true,
      # #   secure: true,
      # #   expires: 1737547197157,
      # #   groups: []
      # # }
      # #
      # ```
      #
      # @param options [Hash] check options. Defaults to nil (a missing argument is rejected with `invalid_arguments`).
      # @option options [String] :identifier identifier to be verified
      # @option options [String] :deviceTag the `deviceTag` as returned by a challenge-response method's result
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Hash] one of the following:
      #   `{valid: true, secure: Boolean, expires: (Integer, nil), groups: Array<String>}`,
      #   `{valid: false, reason: 'revoked'|'unresolved'}`, or
      #   `{error: {code: String, reason?: String, message: String}}`
      #   - `{valid: true, secure: Boolean, expires?: Integer, groups: Array<String>}`: Indicates that the user may remain authenticated. The `secure` property is `true` only when the domain's `triauth` configuration record and every well-formed record of the identity answer (for composite device tags, of both identities' answers) were DNSSEC-validated. The `expires` property, when a number, is the Unix timestamp until which the `check` method need not be called again; it is `nil` when the DNS records carry no TTL - in that case apply your own minimum re-check interval. The `groups` property carries the identity's **current** fully-qualified group names — replace any session-cached groups with this list on every check, so membership changes take effect within the same bound as key revocation.
      #   - `{valid: false, reason: 'revoked'|'unresolved'}`: Indicates that the device may no longer remain authenticated and should be logged out (call `Triauth.authenticate` again to re-authenticate). The `reason` is diagnostic only: `'revoked'` - the device's keys are no longer published in the DNS; `'unresolved'` - the identity itself (or, for a delegated `deviceTag`, the actor's identity) no longer resolves (e.g., the domain is no longer configured for triauth, or has no identity records). A `deviceTag` outside the format of a device tag is reported as `'revoked'` without a DNS lookup.
      #   - `{error: {code: String, reason?: String, message: String}}`: Indicates that there was some problem, and the status cannot be determined at the moment, including an `error` message with more details.
      def self.check(options = nil, config = {})
        config = Helpers.merge_config(config)
        config[:logger] = (config[:logger].respond_to?(:spawn) ? config[:logger].spawn(config[:cid]) : nil) || config[:logger]

        Helpers.log(config, :info, 'Processing Triauth.check')
        ts = Helpers.now

        begin
          # Ensure only recognized options are present to help avoid misspellings.
          if !Helpers.has_only_known_properties(options, %i[identifier deviceTag])
            raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Unrecognized function argument' })
          end

          # Reject config overrides carrying unknown keys
          if !Helpers.has_only_known_properties(config, Triauth::KNOWN_CONFIG_KEYS)
            raise Triauth::Error.new({ code: 'invalid_config', message: 'Unrecognized configuration key' })
          end

          identifier = options[:identifier]
          device_tag = options[:deviceTag]

          Helpers.log(config, :info, 'Request parameters:', { identifier: identifier, deviceTag: device_tag })

          if !Helpers.is_string(identifier) || !Helpers.is_string(device_tag)
            raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Invalid or missing function arguments' })
          end

          # A malformed identifier is a caller error, reported ahead of the device tag verdict
          identifier_error = Validator.validate_identifier(identifier)[:errors][0]
          if identifier_error
            raise Triauth::Error.new(identifier_error)
          end

          # A device tag outside the closed grammar was never minted by a result, so it reads as revoked, with no DNS lookup
          if !Validator.validate_device_tag(device_tag)[:valid]
            Helpers.log(config, :debug, 'Check failed - malformed deviceTag', { identifier: identifier })
            return { valid: false, reason: 'revoked' }
          end

          # Decompose the deviceTag: a direct tag is one component, a delegated tag is three
          parts = device_tag.split(':', -1)
          subject_component, subject_lookup_code = parts[0].split('~', -1)

          # (`Triauth::Identity`, qualified: the bare `Identity` resolves to the `Triauth::Api::Identity` module here;
          # `lookupCode` is nil when absent, exactly as the JS `undefined`)
          identity = Triauth::Identity.new(identifier, { lookupCode: subject_lookup_code }, config)

          identity.resolve

          if !identity.resolved
            Helpers.log(config, :debug, 'Check failed', { reason: 'unresolved', identifier: identifier, deviceTag: device_tag })
            return { valid: false, reason: 'unresolved' }
          end

          # There are two types of deviceTags:
          # - 'direct' ones that directly match the user's device (keyGroup),
          # - 'delegated' ones that were produced by delegated authentication (when `include` was followed), that have ':' in them

          secure = nil
          expires = nil

          # 'direct' deviceTags don't have ':'
          if parts.length == 1

            # Attempt direct match to one of keyGroup tags
            key_group = identity.keys.find_by_tag(subject_component)

            if !key_group
              Helpers.log(config, :debug, 'Check failed - deviceTag revoked', { identifier: identifier, deviceTag: device_tag })
              return { valid: false, reason: 'revoked' }
            end

            secure = identity.secure
            expires = Helpers.earliest(identity.authentication_endpoint.expires, key_group[:expires])

          # 'delegated' deviceTag
          else

            # Decompose the deviceTag for delegated/actor flows into the `include` statement tag, actor's identifier,
            # and actor's device tag; the device component resolves in the actor's zone, so it carries the actor's salt
            include_tag = subject_component
            _, actor_identifier, actor_device_tag_component = parts
            actor_device_tag, actor_lookup_code = actor_device_tag_component.split('~', -1)

            actor_identity = Triauth::Identity.new(actor_identifier, { lookupCode: actor_lookup_code }, config)

            # Verify that there is a matching include statement
            include_statement = identity.includes.find(actor_identity, include_tag, nil)

            if !include_statement
              Helpers.log(config, :debug, 'Check failed - include statement unresolved or revoked', { identifier: identifier, deviceTag: device_tag, includeTag: include_tag })
              return { valid: false, reason: include_statement == false ? 'unresolved' : 'revoked' }
            end

            # Finally, ensure that the actor's deviceTag matches one of actor's keyGroups
            actor_key_group = actor_identity.keys.find_by_tag(actor_device_tag)

            if !actor_key_group
              Helpers.log(config, :debug, 'Check failed - actor deviceTag revoked', { actorIdentifier: actor_identifier, actorDeviceTag: actor_device_tag })
              return { valid: false, reason: 'revoked' }
            end

            secure = identity.secure && actor_identity.secure
            expires = Helpers.earliest(
              Helpers.earliest(identity.authentication_endpoint.expires, include_statement[:expires]),
              Helpers.earliest(actor_identity.authentication_endpoint.expires, actor_key_group[:expires])
            )
          end

          Helpers.log(config, :debug, 'Check successful', { identifier: identifier, deviceTag: device_tag })

          # Enforce config.requireSecure. valid:false (revoked) path stays not gated by design
          ChallengeResponseFlow.assert_secure(secure, config)

          return Helpers.clone(
            {
              valid: true,
              secure: secure,
              expires: expires,
              groups: identity.groups
            }
          )
        rescue StandardError => err
          return Triauth::Error.process(err, config)
        ensure
          Helpers.log(config, :info, "Completed in #{(Helpers.now - ts).round}ms")
        end
      end

      # The `ping` method may be used to re-authenticate the user in background, by obtaining a fresh proof that the user still has access to cryptographic keys.
      # While the `Triauth.check` method ensures only that the keys and the optional delegation used for authentication were not changed or removed from DNS,
      # `Triauth.ping` goes a step further, and requires a fresh, valid signature.
      #
      # Pings typically do not require any interaction from the user, and may be used as one of the signals in Continuous Authentication schemes.
      #
      # > [!NOTE]
      # > **Get the `ping` permission and use the same base callbackUrl as for authentication**<br/>
      # > To get the permission, provide the `ext:{permissions:{ping:true}}` parameter to the `Triauth.authenticate` function during the initial call (i.e., when building the challenge).
      # > The authentication result shows the decision in `ext[:permissions]`. You can call `ping` only when `ext.dig(:permissions, :ping) == true` in the result.
      # >
      # > Also, the `callbackUrl` used in this method must have the **same base URL** (its origin plus the path up to and including the last `/`) as the `callbackUrl` from the initial `Triauth.authenticate` call.
      # > For example, if `callbackUrl` used for authentication was `https://example.com/dir1/callback`, the `callbackUrl` used in this method
      # > must sit in that same `https://example.com/dir1/` base directory — only the final path segment may differ, e.g., `https://example.com/dir1/this-callback` (a deeper path such as `https://example.com/dir1/dir2/this-callback` does **not** match the base URL, and the request will be rejected).
      #
      # The ping is based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
      #
      # **1. Request**
      #
      # At first, you need to call the `Triauth.ping` method with the `identifier` option set to the user provided personal identifier (lowercase string),
      # a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
      # a `sessionKey` (string) option set to the `sessionKey` of a `Triauth.authenticate` result,
      # and an optional `ext` option (Hash) listing the [protocol extensions](#protocol-extensions) that you wish to use.
      #
      # In return, you will receive a Hash with the `challenge` (string) and `redirectUrl` (string).
      # You should temporarily store the `challenge` under the user's session, where the user can't tamper with it, and redirect the user's web browser to the `redirectUrl`.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # result = Triauth.ping({ identifier: identifier, callbackUrl: callback_url, sessionKey: session_key, ext: ext })
      # # returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
      # # returns {error} on error
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      #
      # Triauth.ping(
      #   {
      #     identifier: 'john@triauthdemo.org',
      #     callbackUrl: 'https://example.com/callback',
      #     sessionKey: '59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8'
      #   }
      # )
      # #
      # # {
      # #   challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2FsbGJhY2siLCJ0eXBlIjoicGluZyIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoicWFvU1JnZlVnREpwZG5LX1FnQTd4SG9ZIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjEsImVrIjoiQkVoLTJGR0JOUkUyUGZvSTVsWjh4eU9KX2IzaTlaRVFadGtQOGJVajJ6VWljWDdsaTdqalBvYzVmUnczUlZKb2tjb1BZdVRLdGdGaVVENlR1LURrM3I0In0.urITupCNu0ZNV4CF692qaZs6UaBb5LNov-Z9hhB5ArU',
      # #   redirectUrl: 'https://auth.triauthdemo.org/ping.html#?skid=wzI1sz3n1R4biw4FL_VJ3Q&request=aTO6cylS_52etdEH.hAskvAG-kqxradXNXvr3S4yxpgI3c6EdBOWOnN3UP4CjEfhkyQ1vbcYTmYQ_L3UOtIm6VwPYczazFTW7G7mXByWzAITIVkTRaQHlwyOj9CkPiOP278pc8pQdjPsCKmVHEPSqfwYlnUvNOOp_dsVRgb1zKT2QEkWFnCAH1CUvxDb4bpYqQ_YFa-q48WjkC9cDXRSKRgpN51iwPGV-koSmoIwgYLghNpUC4Cvx72ctYq1tLyP6jrXa3dS8VrSZgy5D4EFwYx22VHg1LloHgDc730QN560wpD7yGL8ylk0eENLml357QTLextpeqZ4Q_MG6JEg0fsN1XdNduNlsiQd_GfTiVwLnaXh3'
      # # }
      # #
      # ```
      #
      # **2. Redirect**
      #
      # Once the user's web browser is redirected to the `redirectUrl`, the Triauth Authenticator web application immediately responds to the `callbackUrl`. This needs a valid session key with the `ping` permission.
      #
      # **3. Verify**
      #
      # The Triauth Authenticator application redirects the user's web browser to the previously provided `callbackUrl`, by default through the [HTTP GET method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/GET), and passes a fresh signature in the `response` URL parameter.
      # The method that is used to pass the response to your application can be configured with [callbackMethod extension](#protocol-extensions).
      #
      # Once you extract the `response` (string), you should pass it to the `Triauth.ping` function together with the previously stored `challenge` (string) to obtain ping result.
      # If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`. Every other option belongs to stage 1 and is rejected here with `invalid_arguments`.
      #
      # > [!WARNING]
      # > **Invalidate the challenge after every ping attempt.**
      # > Only ever pass a `challenge` that your application generated and stored server-side (e.g., in the user's session or your database) - never one taken from user-controlled input.
      # > Upon every ping attempt, make sure to remove or invalidate that stored `challenge`, so that a captured `(challenge, response)` pair cannot be re-used in replay attacks within the `pingTimeout` freshness window. This matters especially for ping, which is meant for frequent, unattended background / Continuous Authentication use.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # ping_result = Triauth.ping({ challenge: challenge, response: response })
      # # returns {pinged:true, issuedAt, signedAt, verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, groups, deviceName, deviceTag, keys} upon success
      # # returns {error:{code, message}} upon error
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.ping(
      #   {
      #     challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2FsbGJhY2siLCJ0eXBlIjoicGluZyIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoicWFvU1JnZlVnREpwZG5LX1FnQTd4SG9ZIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjEsImVrIjoiQkVoLTJGR0JOUkUyUGZvSTVsWjh4eU9KX2IzaTlaRVFadGtQOGJVajJ6VWljWDdsaTdqalBvYzVmUnczUlZKb2tjb1BZdVRLdGdGaVVENlR1LURrM3I0In0.urITupCNu0ZNV4CF692qaZs6UaBb5LNov-Z9hhB5ArU',
      #     response: 'BGb9tY40nX1dXVl8KlCg8c6mSThXTM2UPWvkN_tHT8h05FIbypseeOplJNXLRH3mVtiTT4YarHDUVT5OqmHziOc.AV7MibGdeVKtc2hBh9BfpeB48dxc1xwu1bv2LtfvmHNEXUf_J_g0j3Njndh-_wiUI2sF2s_b8g9WJe5SewgFblFvdKIz6rXNL6SeCZsQeZhIvNSAvMtXgAHJtybBU5MmQJhx0zqh0Rf7Osuju8bceqMHFzuY9083btLzpU6iCbJeKGXqnwAMyCVOOwCDkJgCVRE_Mb2wADTsFpIUiQAQX-k6q0qAaBbZ1bec'
      #   }
      # )
      #
      # #
      # # {
      # #   pinged: true,
      # #   issuedAt: 1787224748449,
      # #   signedAt: 1787224751161,
      # #   verifiedAt: 1787224751262,
      # #   expires: 1787226551262,
      # #   secure: true,
      # #   identifier: "john@triauthdemo.org",
      # #   identityDomain: "john._at.triauthdemo.org",
      # #   lookupCode: "",
      # #   actor: "",
      # #   actorIdentityDomain: "",
      # #   actorLookupCode: "",
      # #   groups: [],
      # #   deviceName: "desktop",
      # #   deviceTag: "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ",
      # #   keys: [
      # #     {
      # #       value: "BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
      # #       options: {
      # #         type: "es256",
      # #         use: "attest,auth,ping,sign,stamp"
      # #       },
      # #       verified: true,
      # #       skipped: false
      # #     }
      # #   ]
      # # }
      # #
      # ```
      #
      # > [!IMPORTANT]
      # > Upon successful pinging, the result Hash will have the `pinged` property set to `true`.
      # > You can also check that the returned `identifier`, `deviceTag`, and `secure` values match your expectations.
      # > Note that `expires` may be nil or arbitrarily low - apply your own minimum re-ping interval, as described for `Triauth.authenticate`.
      # >
      # > Upon failed pinging, the `pinged` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
      #
      # > [!NOTE]
      # > Users may configure a different set of cryptographic keys (that still belongs to the same device) for the purpose of responding to ping requests.
      # > You can assume that the `deviceTag` in `ping` result should be the same as in the original `Triauth.authenticate` response, but the combination of verified/skipped keys may differ.
      #
      # @param options [Hash] ping options. Defaults to `{}` (a missing argument is rejected with `invalid_arguments` by the flow's stage detection, as the JS `undefined` is through `perform`'s own `options = {}` default; an explicit nil is the JS `null`, rejected with `invalid_arguments` by the known-keys guard).
      #
      # @option options [String] :identifier the user provided identifier (stage 1)
      # @option options [String] :callbackUrl an application provided URL to which the user's web browser should be redirected with the response (stage 1)
      # @option options [String] :sessionKey the `sessionKey` of a `Triauth.authenticate` result whose `ext.permissions.ping` is `true`; a stage-1 request without a valid session key returns the error `invalid_session_key` (stage 1, required)
      # @option options [Hash] :ext an optional Hash of protocol extensions to use (e.g., `{callbackMethod:'GET'}`) (stage 1)
      #
      # @option options [String] :challenge a challenge as it was returned by the method after stage 1 call (stage 3)
      # @option options [String] :response a received response, by default delivered as a `response` URL parameter of a GET to the `callbackUrl` (overridable via the `callbackMethod` extension) (stage 3)
      #
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Hash] one of the following:
      #   `{challenge: String, redirectUrl: String}`,
      #   `{pinged: true, issuedAt: Integer, signedAt: Integer, verifiedAt: Integer, expires: (Integer, nil), secure: Boolean, identifier: String, identityDomain: String, lookupCode: String, actor: String, actorIdentityDomain: String, actorLookupCode: String, groups: Array<String>, deviceName: String, deviceTag: String, keys: Array<Hash>}`, or
      #   `{error: {code: String, reason?: String, message: String}}`
      def self.ping(options = {}, config = {})
        # (`options = {}`: a missing argument is the JS `undefined`, which the flow's `perform(type, options = {}, ...)` default turns into `{}` (`invalid_arguments` from the stage detection);
        # a Ruby default applies only at the method called without the argument, so it lives here too, and an explicit nil stays the JS `null` (`invalid_arguments` from the known-keys guard))
        config = Helpers.merge_config(config)
        config[:logger] = (config[:logger].respond_to?(:spawn) ? config[:logger].spawn(config[:cid]) : nil) || config[:logger]

        # No challenge processing needed here
        # (`async () => {}` ignores its argument; a zero-parameter lambda would raise ArgumentError when the flow calls it with the `{challenge}` Hash)
        on_challenge = ->(_args) {}

        on_response = lambda do |args|
          challenge = args[:challenge]
          response = args[:response]

          # Verify the response against the challenge
          result = ChallengeResponseFlow.verify_challenge_response('ping', challenge.challenge_string, challenge, response, config[:pingTimeout], config)

          # Propagate the failure signals unchanged: null -> request_expired, false -> verification_failed.
          return result if !result

          sig = result[:sig]
          verify_result = result[:verifyResult]

          Helpers.log(config, :info, 'Verification successful', { identifier: sig[:identifier], deviceTag: sig[:deviceTag] })

          # (an `expires` of nil stays a present nil member, as in `authenticate`)
          return Helpers.clone(
            {
              pinged: true,

              issuedAt: challenge.data[:iat],
              signedAt: sig[:signedAt],
              verifiedAt: verify_result[:verifiedAt],

              expires: verify_result[:expires],
              secure: verify_result[:secure],

              identifier: sig[:identifier],
              identityDomain: sig[:identityDomain],
              lookupCode: sig[:lookupCode],
              actor: sig[:actor],
              actorIdentityDomain: sig[:actorIdentityDomain],
              actorLookupCode: sig[:actorLookupCode],
              groups: sig[:groups],

              deviceName: sig[:deviceName],
              deviceTag: sig[:deviceTag],
              keys: sig[:keys]
            }
          )
        end

        return ChallengeResponseFlow.perform('ping', options, { onChallenge: on_challenge, onResponse: on_response }, config)
      end
    end
  end
end
