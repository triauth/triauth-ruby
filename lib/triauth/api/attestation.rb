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
require_relative '../validator'
require_relative '../protocol'
require_relative '../challenge_response_flow'

module Triauth
  module Api
    # Methods related to attestations that are a part of the official triauth-ruby API.
    module Attestation
      # The `attest` method may be used to obtain third-party verified attestations related to the given user's `identifier`.
      # You can request attestations of almost anything, like the user age, not-a-robot status, location, role, etc., given that there is a verification provider that provides such attestation.
      #
      # Each attestation consists of a `label` (string) that is displayed to the user (e.g., 'I am not a robot'),
      # and `providers` (array of `https://` URL strings), from which the user can select the desired verification provider.
      # Once the user clicks 'verify' button for the given attestation, they are taken to the selected verification provider URL.
      # It is then the job of verification provider to verify that the user meets the certain criteria (e.g., as read from the URL),
      # and respond with a digital signature. Such signature(s) are embedded in the final response that you receive,
      # and are verified during the stage '3. Verify' call of `Triauth.attest`.
      #
      # > [!IMPORTANT]
      # > **You choose which providers to trust, and the provider defines what the attestation means.**<br/>
      # > `Triauth.attest` only verifies that a signature came from an identity at the host of one of the `providers` you listed. It does not interpret what that provider actually checked.
      #
      # > [!NOTE]
      # > **Attestations in triauth may be anonymous.**<br/>
      # > By default, verification providers receive only the user-selected verification provider URL, and the domain name of user's authentication endpoint (e.g., `auth.triauth.org`).
      # > They can later ask the user for their full identifier if needed and set a constraint that the attestation is valid only for the given identifier.
      #
      # > [!NOTE]
      # > **Binders: what an attestation is tied to.**<br/>
      # > A verification provider that learns the user states it in the `bind` Hash of its signature's signed metadata:
      # > `identifier` (the user's identifier), `via` (the client application), and `deviceTag` (the device that completed the ceremony).
      # > Every member of `bind` is critical, on every signature of the response: an unrecognized binder — or one that does not equal the verified user's value — fails the attestation (`verification_failed`),
      # > so a provider's signed statement can never be silently ignored. Members of the signed metadata outside `bind` are auxiliary, and unrecognized ones are ignored.
      # > An attester that binds nothing attests anonymously (the default); the binders it did state are surfaced under `attestations.<id>.signedMetadata.bind`, so you can require their presence.
      #
      # > [!NOTE]
      # > **Use the same base callbackUrl as for authentication**<br/>
      # > The `callbackUrl` used in this method must have the **same base URL** (its origin plus the path up to and including the last `/`) as the `callbackUrl` from the initial `Triauth.authenticate` call.
      # > For example, if `callbackUrl` used for authentication was `https://example.com/dir1/callback`, the `callbackUrl` used in this method
      # > must sit in that same `https://example.com/dir1/` base directory — only the final path segment may differ, e.g., `https://example.com/dir1/this-callback` (a deeper path such as `https://example.com/dir1/dir2/this-callback` does **not** match the base URL, and the request will be rejected).
      #
      # The attestations are based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
      #
      # **1. Request**
      #
      # At first, you need to call the `Triauth.attest` method with the `identifier` option set to the user provided personal identifier (lowercase string),
      # a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
      # an `attestations` option (Hash) whose keys are caller-chosen attestation IDs and whose values consist of a `label` (string) and `providers` (array of `https://` URL strings),
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
      # result = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: attestations, sessionKey: session_key, ext: ext })
      # # returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
      # # returns {error} on error
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.attest(
      #   {
      #     identifier: 'john@triauthdemo.org',
      #     callbackUrl: 'https://example.com/triauth-callback',
      #     attestations: {
      #       'not-a-robot': {
      #         label: 'I am not a robot',
      #         providers: [
      #           'https://attest.triauth.org/proof-of-work',
      #           'https://other-provider.example.com/i-am/not-a-robot'
      #         ]
      #       }
      #     },
      #     sessionKey: '59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8'
      #   }
      # )
      # # {challenge: 'eyJjYn…l19fX0.PEq5CslSnTExe9xko1O5B-K9T4wBse5XtyClYb8WxJM', redirectUrl: 'https://auth.triauthdemo.org/attest.html#?skid=wzI1sz3n1R4biw4FL_VJ3Q&request=…'}
      # ```
      #
      # **2. Redirect**
      #
      # Once the user's web browser is redirected to the `redirectUrl`, they will be taken to the Triauth Authenticator web application, where they will be presented with the requested attestations.
      # For each attestation, your `label` is shown in the UI, together with a select field listing `providers`, and a 'Verify' button, allowing the user to select the desired provider and complete the attestation.
      #
      # > [!TIP]
      # > The URLs of verification providers are shown in the UI, so keep them short and human-friendly.
      #
      # If the user declines the request, the Triauth Authenticator sends `false` as the `response`, which `Triauth.attest` reports as the error `request_denied`.
      #
      # **3. Verify**
      #
      # The Triauth Authenticator application redirects the user's web browser to the previously provided `callbackUrl`, by default through the [HTTP GET method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/GET), and passes the attestation in the `response` URL parameter.
      # The method that is used to pass the response to your application can be configured with [callbackMethod extension](#protocol-extensions).
      #
      # Once you extract the `response` (string), you should pass it to the `Triauth.attest` function together with the previously stored `challenge` (string) to obtain attestation result.
      # If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`. Every other option belongs to stage 1 and is rejected here with `invalid_arguments`.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # attest_result = Triauth.attest({ challenge: challenge, response: response })
      # # returns {attested:true, issuedAt, signedAt, verifiedAt, expires, secure, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, groups, attestations, deviceName, deviceTag, keys} upon success
      # # returns {error:{code, message}} upon failure
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.attest(
      #   {
      #    challenge: 'eyJjYn…l19fX0.PEq5CslSnTExe9xko1O5B-K9T4wBse5XtyClYb8WxJM',
      #    response: 'BPPDsY…OGSBac'
      #   }
      # )
      #
      # #
      # # {
      # #   attested: true,
      # #   issuedAt: 1787224748449,
      # #   signedAt: 1787224773556,
      # #   verifiedAt: 1787224773991,
      # #   expires: 1787226573991,
      # #   secure: true,
      # #   identifier: "john@triauthdemo.org",
      # #   identityDomain: "john._at.triauthdemo.org",
      # #   lookupCode: "",
      # #   actor: "",
      # #   actorIdentityDomain: "",
      # #   actorLookupCode: "",
      # #   groups: [],
      # #   attestations: {
      # #     'not-a-robot': {
      # #       valid: true,
      # #       type: "attest",
      # #       identifier: "proof-of-work@attest.triauth.org",
      # #       identityDomain: "proof-of-work._at.attest.triauth.org",
      # #       lookupCode: "",
      # #       actor: "",
      # #       actorIdentityDomain: "",
      # #       actorLookupCode: "",
      # #       via: "https://attest.triauth.org/proof-of-work",
      # #       ver: 1,
      # #       signedAt: 1787224768930,
      # #       verifiedAt: 1787224773991,
      # #       publicProfile: {
      # #         name: "Proof Of Work"
      # #       },
      # #       groups: [],
      # #       deviceName: "server",
      # #       deviceTag: "NOtejuAqKHSdgvKVpw57cU_Qipj6UKcz2nNiugx0l8g",
      # #       keys: [
      # #         {
      # #           value: "BAdEISRVd_8LuQe8SV6p-cDjW2t3PSa6NlRGIhfRflkvIA9rrNJWbsQllN56YpF2Q8AIHWrcWcR6hoSnXy7QLFM",
      # #           options: {
      # #             use: "attest",
      # #             type: "es256"
      # #           },
      # #           verified: true,
      # #           skipped: false
      # #         }
      # #       ],
      # #       secure: true,
      # #       expires: 1787226573991,
      # #       signedMetadata: {
      # #         bits: 16
      # #       },
      # #       unsignedMetadata: {}
      # #     }
      # #   },
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
      # > Upon successful attestation, the result Hash will have the `attested` property set to `true`.
      # >
      # > Upon failed attestation, the `attested` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
      #
      # When `attested` is `true`, inspect the result before relying on it:
      # - Check `secure`. It is `true` only when DNSSEC protected every DNS record of every identity involved in verification (the user's and every attester's, including each domain's `triauth` configuration record). When it is `false`, some of the public keys read from DNS were not cryptographically protected.
      # - For attestations that must be tied to this specific user, confirm that the per-attestation `attestations.<id>.signedMetadata.bind` carries the binding you expect (the `identifier`/`deviceTag`).
      # - Compare `attestations.<id>.identifier` with the attester the provider documents when the provider's host also issues identities to others.
      #
      # @param options [Hash] attestation options. Defaults to nil (a missing argument is rejected with `invalid_arguments`, as the empty Hash is).
      #
      # @option options [String] :identifier the user provided identifier (stage 1)
      # @option options [String] :callbackUrl an application provided URL to which the user's web browser should be redirected with the response (stage 1)
      # @option options [Hash] :attestations a Hash whose keys are caller-chosen attestation IDs (printable ASCII) and whose values are `{label, providers}` Hashes describing each requested attestation; at most 4 attestations, each listing at most 4 `https://` provider URLs (error `invalid_attestations` otherwise) (stage 1)
      # @option options [String] :sessionKey the `sessionKey` of a `Triauth.authenticate` result; a stage-1 request without a valid session key returns the error `invalid_session_key` (stage 1, required)
      # @option options [Hash] :ext an optional Hash of protocol extensions to use (e.g., `{callbackMethod:'GET'}`) (stage 1)
      #
      # @option options [String] :challenge a challenge as it was returned by the method after stage 1 call (stage 3)
      # @option options [String] :response a received response, by default delivered as a `response` URL parameter of a GET to the `callbackUrl` (overridable via the `callbackMethod` extension) (stage 3)
      #
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Hash] one of the following:
      #   `{challenge: String, redirectUrl: String}`,
      #   `{attested: true, issuedAt: Integer, signedAt: Integer, verifiedAt: Integer, expires: (Integer, nil), secure: Boolean, identifier: String, identityDomain: String, lookupCode: String, actor: String, actorIdentityDomain: String, actorLookupCode: String, groups: Array<String>, attestations: Hash, deviceName: String, deviceTag: String, keys: Array<Hash>}`, or
      #   `{error: {code: String, reason?: String, message: String}}`
      #   - `{challenge: String, redirectUrl: String}`: Returned during stage 1 when a challenge is generated. The `challenge` should be stored and the user should be redirected to the `redirectUrl`.
      #   - `{attested: true, issuedAt: Integer, signedAt: Integer, verifiedAt: Integer, expires?: Integer, secure: Boolean, identifier: String, identityDomain: String, lookupCode: String, actor: String, actorIdentityDomain: String, actorLookupCode: String, groups: Array<String>, attestations: Hash, deviceName: String, deviceTag: String, keys: Array<Hash>}`: Returned during stage 3 upon successful attestation. Includes:
      #     - `attested` (true): Indicates the attestation request was fully satisfied (user signature plus every requested attester signature verified).
      #     - `issuedAt` (Integer): Unix timestamp on **your** server's clock at which you issued the challenge in stage 1 — the start of the flow's timeline.
      #     - `signedAt` (Integer): Unix timestamp on the **user's device** clock at which the user signed the request (the user's `mainSig`). Verified to fall within the freshness window, but device-asserted — do not treat it as a trusted wall clock; prefer `issuedAt`/`verifiedAt` for authoritative timing. Each attester's own signing time is on its `attestations.<id>.signedAt`.
      #     - `verifiedAt` (Integer): Unix timestamp on **your** server's clock at which the whole bundle finished verifying — the latest (max) across the user's and every attester's signature confirmation.
      #     - `expires` (Integer, optional): Unix timestamp at which the overall verification expires — the earliest expiry across all signing identities; `nil` when none of the DNS records involved carried a TTL, in which case apply your own re-check interval.
      #     - `secure` (Boolean): True only when, for every identity involved (the user's and every attester's), DNSSEC was reported for the domain's `triauth` configuration record and for every well-formed record of the identity answer; a single non-validated identity record anywhere degrades it.
      #     - `identifier` (String): The user's identifier (from the user's `mainSig`).
      #     - `identityDomain` (String): The DNS domain under which the user's identity records are stored (the user's own, for a delegated ceremony).
      #     - `lookupCode` (String): The lookup code the user identity's domain derivation consumed (under `mode=private`); `''` where none was. Each `attestations.<id>.lookupCode` names the attester's own likewise.
      #     - `actor` (String): The identifier of the delegate whose keys signed the user's `mainSig` (delegated ceremony), or `''` when the user's own keys signed it. Attester signatures are always first-party (their own `actor` is `''`).
      #     - `actorIdentityDomain` (String): For a delegated ceremony, the DNS domain under which the delegate's identity records are stored — the records the signing keys were read from; `''` when the user's own keys signed it (and always `''` on attester entries).
      #     - `actorLookupCode` (String): The lookup code the delegate's domain derivation consumed; `''` where none was (and always `''` on attester entries - their statements are first-party).
      #     - `groups` (Array): The user's fully-qualified group-membership claims (sorted, deduplicated; `[]` when none are published). This top-level field describes the user, while each `attestations.<id>.groups` describes that attester's own identity.
      #     - `attestations` (Hash): A map keyed by the caller-chosen attestation ID, whose values are the per-attester signature Hashes (same shape as `Triauth::Signature#verify` returns: `{valid, type:'attest', identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, via, ver, signedAt, verifiedAt, publicProfile, groups, deviceName, deviceTag, keys, secure, expires, signedMetadata, unsignedMetadata}`).
      #     - `deviceName` (String): User-given, public name of the device that signed the request.
      #     - `deviceTag` (String): Unique identifier of the device (and, for a delegated ceremony, the delegation) that signed the request, in the same form `Triauth.authenticate` reports it.
      #     - `keys` (Array): Public keys considered and/or used to verify the user's signature.
      #   - `{error: {code: String, reason?: String, message: String}}`: Returned during stage 1 or stage 3 when attestation fails, includes an error Hash with code and message.
      def self.attest(options = nil, config = {})
        config = Helpers.merge_config(config)
        config[:logger] = (config[:logger].respond_to?(:spawn) ? config[:logger].spawn(config[:cid]) : nil) || config[:logger]

        # `Object.assign({}, options)`: nil, a String or an Array in the options position give the same Hash as in JS
        options = Helpers.object_assign({}, options)
        attestations_option = options[:attestations]

        validate_attestations = lambda do |attestations|
          validation_error = Validator.validate_attestations(attestations)[:errors][0]

          if validation_error
            raise Triauth::Error.new(validation_error)
          end
        end

        on_challenge = lambda do |args|
          challenge = args[:challenge]
          validate_attestations.call(attestations_option)
          challenge.data[:attest] = attestations_option
        end

        on_response = lambda do |args|
          challenge = args[:challenge]
          response = args[:response]
          attestations = challenge.data[:attest]
          validate_attestations.call(attestations)

          # For attestations the signature is verified against the SHA256 of challengeString
          signed_payload = Helpers.sha256(challenge.challenge_string)

          attest_timeout = config[:attestTimeout]
          verify_result = response.verify(
            'attest',
            signed_payload,
            challenge,
            {
              notBefore: Helpers.date_now - (attest_timeout.nil? || attest_timeout == 0 ? 0 : attest_timeout), # `config.attestTimeout || 0`: the JS falsy set of a number, nil and 0
              notAfter: Helpers.date_now,
              minSignatures: 1,
              maxSignatures: [attestations.keys.length + 1, Protocol::LIMITS[:maxMultiSignatures] || 0].min # `LIMITS.maxMultiSignatures || 0`: a frozen Integer constant, so Ruby's `||` yields the same value
            }
          )

          # `verifyResult?.valid`: the result is a Hash, nil or false
          if verify_result && verify_result[:valid] && verify_result[:signatures].length > 0

            # Protocol invariant: the user's signature is always the first element of the
            # multi-signature envelope; the remaining entries are attester signatures.
            main_sig = verify_result[:signatures][0]

            if challenge.identity.identifier != main_sig[:identifier]
              Helpers.log(config, :debug, 'Verification failed - identifier mismatch', { expectedIdentifier: challenge.identity.identifier, receivedIdentifier: main_sig[:identifier] })
              return false
            end

            if !Validator.validate_callback_url(challenge.data[:cburl])[:valid] ||
               Helpers.get_base_url(challenge.data[:cburl]) != main_sig[:via]
              Helpers.log(config, :debug, 'Verification failed - via prefix mismatch', { cburl: challenge.data[:cburl], via: main_sig[:via] })
              return false
            end

            # What a binder must equal, by name: the verified user signature's own fields.
            binder_targets = {
              identifier: main_sig[:identifier], # the user the attestation is bound to
              via: main_sig[:via],               # the client application the user signed for
              deviceTag: main_sig[:deviceTag]    # the device that completed the ceremony
            }

            # Verify binders - a verifier's statement about WHOM it verified
            # An envelope carrying a false or unrecognized binding is malformed as a whole.
            # (`Object.entries(sig.signedMetadata.bind || {})`: `object_assign({}, x)` yields `{}` for the JS-falsy values and spreads a
            # String or an Array into index keys exactly as `Object.entries` lists them; an unknown binder compares to `undefined` in JS,
            # which no value equals, while Ruby's nil would equal a JSON null value, hence the explicit `key?` test)
            verify_result[:signatures].each do |sig|
              if !Validator.validate_binders(sig[:signedMetadata])[:valid] ||
                 !Helpers.object_assign({}, sig[:signedMetadata][:bind]).all? { |binder, value| binder_targets.key?(binder) && value == binder_targets[binder] }
                Helpers.log(config, :debug, 'Verification failed - invalid or mismatched binders', { identifier: sig[:identifier], signedMetadata: sig[:signedMetadata] })
                return false
              end
            end

            attestations_result = {}

            # Note: a single attestSig can satisfy multiple requested attestation IDs if their providers` lists overlap # rubocop:disable Style/CommentAnnotation -- the triauth-js comment, carried verbatim
            # (`Object.entries(attestations)`: the JS object key order, an all-digit attestation ID first)
            Helpers.ordered_entries(attestations).each do |attest_id, entry|
              providers = entry[:providers]
              matched = false

              verify_result[:signatures][1..].each do |attest_sig| # `slice(1)`
                # (`/.+@/` with the JS `.`; `indexOf(...) >= 0` on an Array of validated URL strings is `include?`)
                if attest_sig[:valid] &&
                   attest_sig[:actor] == '' && # attester statements must be self-signed
                   providers.include?(attest_sig[:via]) &&
                   attest_sig[:identifier].sub(/#{Helpers::JS_DOT}+@/o, '') == Helpers.url_host(attest_sig[:via])
                  Helpers.log(config, :debug, 'Attestation matched', { attestId: attest_id, attestSig: attest_sig })
                  attestations_result[attest_id] = Helpers.object_assign({}, attest_sig)
                  matched = true
                  break
                end
              end

              if !matched
                Helpers.log(config, :info, 'Verification failed - missing or unverified attestation', { attestId: attest_id })
                return false
              end
            end

            Helpers.log(config, :info, 'Verification successful', { identifier: main_sig[:identifier], deviceTag: main_sig[:deviceTag], attestations: attestations_result.keys })

            # (an `expires` of nil stays a present nil member, as in `authenticate`)
            return Helpers.clone(
              {
                attested: true,

                issuedAt: challenge.data[:iat],
                signedAt: main_sig[:signedAt],
                verifiedAt: verify_result[:verifiedAt],

                expires: verify_result[:expires],
                secure: verify_result[:secure],

                identifier: main_sig[:identifier],
                identityDomain: main_sig[:identityDomain],
                lookupCode: main_sig[:lookupCode],
                actor: main_sig[:actor],
                actorIdentityDomain: main_sig[:actorIdentityDomain],
                actorLookupCode: main_sig[:actorLookupCode],
                groups: main_sig[:groups],

                attestations: attestations_result,

                deviceName: main_sig[:deviceName],
                deviceTag: main_sig[:deviceTag],
                keys: main_sig[:keys]
              }
            )

          elsif verify_result.nil?
            # `parseInt(challenge.data.iat, 10)` of a number: a non-number (or a non-finite one) logs `NaN` there and nil here - log data only
            Helpers.log(config, :info, 'Verification failed - request expired', { identifier: challenge.identity.identifier, iat: Helpers.is_number(challenge.data[:iat]) && challenge.data[:iat].finite? ? challenge.data[:iat].to_i : nil })
            return nil

          else
            Helpers.log(config, :info, 'Verification failed', { identifier: challenge.identity.identifier })
            return false

          end
        end

        return ChallengeResponseFlow.perform('attest', options, { onChallenge: on_challenge, onResponse: on_response }, config, %i[attestations])
      end
    end
  end
end
