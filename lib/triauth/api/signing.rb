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
require_relative '../challenge_response_flow'
require_relative '../multi_signature'

module Triauth
  module Api
    # Methods related to signing and signature verification that are a part of the official triauth-ruby API.
    module Signing
      # Shared implementation for `Triauth.sign` and `Triauth.stamp`.
      # Embeds `message` (and, for `sign`, optional `attachments`) into the challenge,
      # then verifies the response is a single fresh signature over the same `message`
      # with matching attachments. Attachments are rejected for `stamp`.
      # Freshness is bounded by `config[:signTimeout]` or `config[:stampTimeout]`.
      #
      # @api private
      # @param type [String] `'sign'` or `'stamp'`
      # @param options [Hash] same shape as the corresponding public `sign`/`stamp` method. Defaults to nil (the public methods pass their argument through).
      # @param config [Hash] optional overrides for the global `Triauth.config` settings. Defaults to `{}`.
      # @return [Hash] same return shape as the corresponding public method
      def self.perform(type, options = nil, config = {})
        config = Helpers.merge_config(config)
        config[:logger] = (config[:logger].respond_to?(:spawn) ? config[:logger].spawn(config[:cid]) : nil) || config[:logger]

        # `Object.assign({}, options)`: nil, a String or an Array in the options position give the same Hash as in JS
        options = Helpers.object_assign({}, options)

        message_option = options[:message]
        attachments_provided = options.key?(:attachments) # `'attachments' in options`
        attachments_option = options[:attachments]

        validate_message = lambda do |message|
          validation_error = Validator.validate_message(message)[:errors][0]

          if validation_error
            raise Triauth::Error.new(validation_error)
          end
        end

        validate_attachments = lambda do |attachments, require_source_url = true|
          validation_error = Validator.validate_attachments(attachments, require_source_url)[:errors][0]

          if validation_error
            raise Triauth::Error.new(validation_error)
          end
        end

        on_challenge = lambda do |args|
          challenge = args[:challenge]
          validate_message.call(message_option)
          challenge.data[:msg] = message_option

          if type == 'sign'
            validate_attachments.call(attachments_option.nil? ? [] : attachments_option) # `attachmentsOption ?? []`
            challenge.data[:attachments] = attachments_option.nil? ? [] : attachments_option

          elsif attachments_provided
            raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Attachments option may only be used with Triauth.sign function' })
          end
        end

        on_response = lambda do |args|
          challenge = args[:challenge]
          response = args[:response]
          message = challenge.data[:msg]
          validate_message.call(message)

          challenge_attachments = challenge.data[:attachments]

          if type == 'sign'
            validate_attachments.call(challenge_attachments)

          elsif challenge.data.key?(:attachments)
            raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Attachments option may only be used with Triauth.sign function' })

          end

          # Sign/stamp signatures cover the `msg` (plus the identity header and `ts`), but NOT the
          # challenge nonce/iat/cburl. This makes stamps portable across verifiers (within the `ts` window).
          result = ChallengeResponseFlow.verify_challenge_response(type, message, challenge, response, (type == 'sign' ? config[:signTimeout] : config[:stampTimeout]), config)

          # Propagate the failure signals unchanged: null -> request_expired, false -> verification_failed.
          if !result
            return result
          end

          sig = result[:sig]
          verify_result = result[:verifyResult]

          # (`sig[:signedMetadata]` is always a Hash: the envelope parser guarantees it; `?? []` is the nil test, and the nested
          # ternary is an `if` expression: RuboCop `Style/NestedTernaryOperator`)
          response_attachments =
            if type == 'sign'
              sig[:signedMetadata][:attachments].nil? ? [] : sig[:signedMetadata][:attachments]
            else
              sig[:signedMetadata][:attachments]
            end

          if type == 'sign'
            # `sourceUrl` is optional on the signed response - the proof binds only name+sha256, and the
            # authenticator should not embed fetch URLs (which may carry credentials) in a portable signature.
            validate_attachments.call(response_attachments, false)

          elsif sig[:signedMetadata].key?(:attachments)
            Helpers.log(config, :info, 'Verification failed - stamp response signed-metadata carries attachments', { identifier: sig[:identifier] })
            return false

          end

          if type == 'sign'
            # Attachments are matched by name+sha256. `sourceUrl` is optional but if present must match too.
            # (`ca.sha256 &&`: the JS falsy set of the validated hex string spelled out; `ra.sourceUrl === undefined` is
            # "member absent", so a signed `sourceUrl: null` keeps the JS null outcome, which `validate_attachments` already rejected with `invalid_attachments`)
            attachments_match = lambda do |ca, ra|
              ca[:name] == ra[:name] &&
                !ca[:sha256].nil? && ca[:sha256] != '' && ca[:sha256] == ra[:sha256] &&
                (!ra.key?(:sourceUrl) || ra[:sourceUrl] == ca[:sourceUrl])
            end

            # (`every(... find(...))`: `find` answers the element or undefined, so `any?` is the same test)
            attachments_verify_result =
              challenge_attachments.length == response_attachments.length &&
              challenge_attachments.all? { |ca| response_attachments.any? { |ra| attachments_match.call(ca, ra) } } &&
              response_attachments.all? { |ra| challenge_attachments.any? { |ca| attachments_match.call(ca, ra) } }

            if !attachments_verify_result
              Helpers.log(config, :info, 'Verification failed - not all attachments have been signed', { identifier: sig[:identifier] })
              return false
            end
          end

          Helpers.log(config, :info, 'Verification successful', { identifier: sig[:identifier], deviceTag: sig[:deviceTag] })

          retval = {}
          verb = "#{type}ed"
          retval[verb.to_sym] = true # the result key `:signed` / `:stamped`, a Symbol like every data key

          # `Object.assign(retval, {...})` mutates and returns `retval`: so does `Hash#merge!` (`Helpers.object_assign` would return a new Hash)
          retval.merge!(
            {
              result: response.response_string,
              issuedAt: challenge.data[:iat],
              signedAt: sig[:signedAt],
              verifiedAt: verify_result[:verifiedAt],
              verificationResult: verify_result[:signatures][0]
            }
          )

          return Helpers.clone(retval)
        end

        return ChallengeResponseFlow.perform(type, options, { onChallenge: on_challenge, onResponse: on_response }, config, %i[message attachments])
      end
      private_class_method :perform

      # The `sign` method may be used to obtain an interactive signature of a given `message` and optional `attachments` from the user with a given `identifier`.
      # Interactive signatures require interaction from the user, like reviewing the message and clicking on the 'Sign' button in the Triauth Authenticator.
      # Signatures generated by the `sign` function may be later verified by any party using the `Triauth.verify` method, and may act as an independent proof that e.g.,
      # user has accepted certain terms or documents.
      #
      # > [!WARNING]
      # > A `sign` result is a transferable proof, not a single-use act. The cryptographic signature covers
      # > the `message` (and any `attachments`) together with the signature's own `type`, `identifier`, `via`,
      # > and timestamp — but **not** the challenge nonce, which is never bound to the signature and is not
      # > re-checked during verification. A `sign` response therefore re-verifies against any freshly minted
      # > `sign` challenge for the same `(identifier, message, callbackUrl-base)` while its timestamp is within
      # > `config[:signTimeout]` (30 minutes by default, widened by `config[:maximalAllowedClientClockDrift]`), and
      # > the raw `result` is independently verifiable via `Triauth.verify` until the signer's DNS keys rotate.
      # > Relying parties that need single-use / replay protection must embed a fresh, verifier-chosen nonce
      # > inside the `message` itself and reject reused nonces.
      #
      # > [!NOTE]
      # > **Use the same base callbackUrl as for authentication**<br/>
      # > The `callbackUrl` used in this method must have the **same base URL** (its origin plus the path up to and including the last `/`) as the `callbackUrl` from the initial `Triauth.authenticate` call.
      # > For example, if `callbackUrl` used for authentication was `https://example.com/dir1/callback`, the `callbackUrl` used in this method
      # > must sit in that same `https://example.com/dir1/` base directory — only the final path segment may differ, e.g., `https://example.com/dir1/this-callback` (a deeper path such as `https://example.com/dir1/dir2/this-callback` does **not** match the base URL, and the request will be rejected).
      #
      # The signing is based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
      #
      # **1. Request**
      #
      # At first, you need to call the `Triauth.sign` method with the `identifier` option set to the user provided personal identifier (lowercase string),
      # a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
      # a `message` (string) option set to a human-readable text message to be signed,
      # an optional `attachments` (array) option listing additional file attachments to be covered by the signature,
      # a `sessionKey` (string) option set to the `sessionKey` of a `Triauth.authenticate` result,
      # and an optional `ext` option (Hash) listing the [protocol extensions](#protocol-extensions) that you wish to use.
      #
      # > [!NOTE]
      # > The `message` may consist of letters and digits from any language, space, and a fixed set of punctuation, and is limited to 2 KB.
      # > Emojis, newlines, tabs, and other whitespace or control characters are not allowed - the same rule as for `Triauth.stamp`.
      #
      # The `attachments` option, if present, should be an array (of at most 10 entries) with information on additional file attachments that need to be downloaded and covered by the signature.
      # Each entry in the `attachments` array should be in the form of `{name, sourceUrl, sha256}`, where `name` is a unique attachment's file name, `sourceUrl` is the URL from which the attachment can be downloaded, and `sha256` is a SHA256 hexdigest of the attachment file content.
      #
      # > [!TIP]
      # > The server from which attachment is served must respond with `Access-Control-Allow-Origin: *` HTTP header to allow Triauth Authenticator to download it.
      # > Additionally, only selected file formats and extensions are supported (`.txt`, `.pdf`, `.json`, `.xml`, `.png`, `.doc`, `.xls`, and a few others).
      # > For file formats other than `txt` and `pdf`, the file name must end with the appropriate extension (e.g., `.doc`).
      #
      # > [!TIP]
      # > You can get a SHA256 hexdigest of a content of a given `sourceUrl` with the following snippet:<br/>
      # > ```ruby
      # > Digest::SHA256.hexdigest(Net::HTTP.get(URI(source_url)))
      # > ```
      #
      #
      # In return, you will receive a Hash with the `challenge` (string) and `redirectUrl` (string).
      # You should temporarily store the `challenge` under the user's session, where the user can't tamper with it, and redirect the user's web browser to the `redirectUrl`.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # result = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, attachments: attachments, sessionKey: session_key, ext: ext })
      # # returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
      # # returns {error} on error
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.sign(
      #   {
      #     identifier: 'john@triauthdemo.org',
      #     callbackUrl: 'https://example.com/triauth-callback',
      #     message: 'To continue, please read and accept the attached License',
      #     attachments: [
      #       {
      #         name: 'License',
      #         sourceUrl: 'https://raw.githubusercontent.com/spdx/license-list-data/refs/heads/main/text/AGPL-3.0-or-later.txt',
      #         sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
      #       }
      #     ],
      #     sessionKey: '59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8'
      #   }
      # )
      # # {
      # #   challenge: "eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzaWduIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJLRXZCSVBLZFRLX1JNYldFUkZVVFpBcUkiLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MSwiZWsiOiJCTEYxdEVWQkVZMGpBZ3lFcGM0MUJSdTRHS2loaTVneDhyalFmY2Q3UnFOUGFUd1kyeG1zYkNSZ0YxNkN5VWJuRk5XUFREZndkMV9XTVlEWldRdWFOblkiLCJtc2ciOiJUbyBjb250aW51ZSwgcGxlYXNlIHJlYWQgYW5kIGFjY2VwdCB0aGUgYXR0YWNoZWQgTGljZW5zZSIsImF0dGFjaG1lbnRzIjpbeyJuYW1lIjoiTGljZW5zZSIsInNvdXJjZVVybCI6Imh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9zcGR4L2xpY2Vuc2UtbGlzdC1kYXRhL3JlZnMvaGVhZHMvbWFpbi90ZXh0L0FHUEwtMy4wLW9yLWxhdGVyLnR4dCIsInNoYTI1NiI6ImQ4YTZjYzMxYWJjMTZiNjc0OGM3YTIxZjIxNjExZjVhMWVjMzNmNjdkMjJjYTIzZDdkYTFjMTliOTU0OTZiZWUifV19.zN__zhGHx9hT7gakwy1WZ33JRURklZVmS-crUohEchE",
      # #   redirectUrl: "https://auth.triauthdemo.org/sign.html#?skid=wzI1sz3n1R4biw4FL_VJ3Q&request=23luwOGXdIM6JX8f._EkvQKPuF6kR2v-ur9aIU1QkqCDURnpq-_GThw669vCmekrNYmLC6ZaVuqHLy3i77tFqNUed5hlm-Yk1KLkyroMGnQQl5_jS7CPrwTthn0MjrHrf0hBcVBdeD_3mGTm-wFDjXS6qpgZO9721poQnV3Cj-a6rxQXyX6o1tOD8_JdiEql23uFQ8axvbnpFVP7w-QLj9IuNU6jeM2hOGNrS-n6TKR11iQ40bfyERFWNtQNgrDTh1A_fnnxv_YPTTBdnzgFiDe09M0h93ZACRVJGLWNGj4dx4xsa5l08cC0-6a1BwuShxbMtoWROFLky0vUNkbAseko-4xKvuIIXAu5AmPDTXfLpiormgzmGK72f0aokY1YUUy0VzGIsTDdjCxqPJTgrDlt4g1uJu60yfSCPdHOWubbRj5eMdhTW3p6LzOWIDZPDpSeC141v9eX7wbTB_KIJiJwCvHD1dbq3fTaTM0z313WzT8VXKc5RPtaIWz8J1L7KiZcH2NjjyqFRJ1jYHPj2g8JPiPo5wohmcuPqC98l7cBPK_GI0PXEuuWvuEqk9uDXtufhBHwu2wLOx-n2n9ktLHnE1Bgw5qkYn6-YJD5NJ1YCjljc4_Une_smlyXL6-cDm-dD3ugp1rw1SbVv_f5m8uQUvkHxkxKXrSqSmljxFsG4g9kbf3myh39d5iODAxuwzLcGdOAXWHmIS9Hmkx2rLytc-v8emjPu9Ktb5iD0yZtKAX4-3eWBHzBgPr3wbA"
      # # }
      # ```
      #
      # **2. Redirect**
      #
      # Once the user's web browser is redirected to the `redirectUrl`, they will be taken to the Triauth Authenticator web application,
      # where they will be presented with the message, and have an opportunity to view and/or download attachments.
      #
      # If the user declines the signing request, the Triauth Authenticator sends `false` as the `response`, which `Triauth.sign` reports as the error `request_denied`.
      #
      # **3. Verify**
      #
      # After the user approves the signing request, the Triauth Authenticator application redirects the user's web browser to the previously provided `callbackUrl`, by default through the [HTTP GET method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/GET), and passes a signature in the `response` URL parameter.
      # The method that is used to pass the response to your application can be configured with [callbackMethod extension](#protocol-extensions).
      #
      # Once you extract the `response` (string), you should pass it to the `Triauth.sign` function together with the previously stored `challenge` (string) to obtain signing result.
      # If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`. Every other option belongs to stage 1 and is rejected here with `invalid_arguments`.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # signing_result = Triauth.sign({ challenge: challenge, response: response })
      # # returns {signed:true, result, issuedAt, signedAt, verifiedAt, verificationResult} upon success
      # # returns {error:{code, message}} upon failure
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.sign(
      #   {
      #    challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzaWduIiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJLRXZCSVBLZFRLX1JNYldFUkZVVFpBcUkiLCJpYXQiOjE3ODcyMjQ3NDg0NDksInZlciI6MSwiZWsiOiJCTEYxdEVWQkVZMGpBZ3lFcGM0MUJSdTRHS2loaTVneDhyalFmY2Q3UnFOUGFUd1kyeG1zYkNSZ0YxNkN5VWJuRk5XUFREZndkMV9XTVlEWldRdWFOblkiLCJtc2ciOiJUbyBjb250aW51ZSwgcGxlYXNlIHJlYWQgYW5kIGFjY2VwdCB0aGUgYXR0YWNoZWQgTGljZW5zZSIsImF0dGFjaG1lbnRzIjpbeyJuYW1lIjoiTGljZW5zZSIsInNvdXJjZVVybCI6Imh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9zcGR4L2xpY2Vuc2UtbGlzdC1kYXRhL3JlZnMvaGVhZHMvbWFpbi90ZXh0L0FHUEwtMy4wLW9yLWxhdGVyLnR4dCIsInNoYTI1NiI6ImQ4YTZjYzMxYWJjMTZiNjc0OGM3YTIxZjIxNjExZjVhMWVjMzNmNjdkMjJjYTIzZDdkYTFjMTliOTU0OTZiZWUifV19.zN__zhGHx9hT7gakwy1WZ33JRURklZVmS-crUohEchE',
      #    response: 'BFUYnuW1tUiltgq1DQbLeqpZTNDwDJm89hxkfrBuuNNdTmmwoRYuR5dZeVdnrJWbcSiLfO2VPYuTw-mBq6EZi0c.HUJzImw0j-Uo629gvuIMb6ePe9G835vaz7bURvqz5ICtkxc9vP4sRRXTnkhpQl8lsVVX4aYs1ltz-eft2aqxyUwfaaPYRPhWGj3rwUdr9lXnT8qtSkyInacgxWWx8MCPoveO1GBBD2iIE4-o9vUEfPziEh9dz7bBf_1Y_xM_fFXHEXZaGz1CWBN42S24BnKuVUvcT1gGfJiSIDdoG8YdU6xUFWJwhxwZupQbjIbfGuXrwXVrVejuE3_sgIy7pQ2SyLgSQcoBw329vTJns0b5QcjyRojzc9dS1iWeQWj_3TjF7nQh8F9sHWVqvdc0YCDncrcR_z-uTjDhgzShnhevHXukgQ_-Dze4kOd1wgUiwfEEIQvclIyVkSyrEcMt9bIUkmhb5Su5eicMnzdEZIvLMJQ7gssUxPE8B7_DXKZgMEnH'
      #   }
      # )
      # #
      # # {
      # #   signed: true,
      # #   result: "|sign;john@triauthdemo.org;;https://example.com/;v1;1787224774435;eyJhdHRhY2htZW50cyI6W3sibmFtZSI6IkxpY2Vuc2UiLCJzaGEyNTYiOiJkOGE2Y2MzMWFiYzE2YjY3NDhjN2EyMWYyMTYxMWY1YTFlYzMzZjY3ZDIyY2EyM2Q3ZGExYzE5Yjk1NDk2YmVlIn1dfQ;;pj0gdEVQ3JBYh08jknFpY45WX462AUb1z78mINHewl1NXWzU5_g9ibD3-ffbdH9SIGtQTtcHQrsa3Ivt1wg1sg|",
      # #   issuedAt: 1787224748449,
      # #   signedAt: 1787224774435,
      # #   verifiedAt: 1787224774536,
      # #   verificationResult: {
      # #     valid: true,
      # #     type: "sign",
      # #     identifier: "john@triauthdemo.org",
      # #     identityDomain: "john._at.triauthdemo.org",
      # #     lookupCode: "",
      # #     actor: "",
      # #     actorIdentityDomain: "",
      # #     actorLookupCode: "",
      # #     via: "https://example.com/",
      # #     ver: 1,
      # #     signedAt: 1787224774435,
      # #     verifiedAt: 1787224774536,
      # #     publicProfile: {
      # #       initials: "JD",
      # #       name: "John Doe"
      # #     },
      # #     groups: [],
      # #     deviceName: "desktop",
      # #     deviceTag: "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ",
      # #     keys: [
      # #       {
      # #         value: "BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
      # #         options: {
      # #           type: "es256",
      # #           use: "attest,auth,ping,sign,stamp"
      # #         },
      # #         verified: true,
      # #         skipped: false
      # #       }
      # #     ],
      # #     secure: true,
      # #     expires: 1787226574536,
      # #     signedMetadata: {
      # #       attachments: [
      # #         {
      # #           name: "License",
      # #           sha256: "d8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee"
      # #         }
      # #       ]
      # #     },
      # #     unsignedMetadata: {}
      # #   }
      # # }
      # #
      # ```
      #
      # > [!IMPORTANT]
      # > Upon successful signing, the result Hash will have the `signed` property set to `true`, and the raw signature (string) available in the `result` property.
      # > This signature may also be verified by third parties using the `Triauth.verify` method.
      # >
      # > Upon failed signing, the `signed` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
      #
      # > [!NOTE]
      # > An attachment is bound to the signature by its `name` and `sha256` only. The `sourceUrl` is used at request time to fetch the file, but is optional in the signed response. If a response does sign a `sourceUrl`, it must match the one requested in the challenge.
      #
      # @param options [Hash] signing options. Defaults to nil (a missing argument is rejected with `invalid_arguments`, as the empty Hash is).
      #
      # @option options [String] :identifier (stage 1) the user provided identifier
      # @option options [String] :callbackUrl (stage 1) an application provided URL to which the user's web browser should be redirected with the response
      # @option options [String] :message (stage 1) a human-readable text message to be signed
      # @option options [Array<Hash>] :attachments (stage 1) optional list of at most 10 attachments to be covered by the signature, each `{name: String, sourceUrl: String, sha256: String}`; `name` must be unique within the list and `sha256` a lowercase hex digest
      # @option options [String] :sessionKey (stage 1, required) the `sessionKey` of a `Triauth.authenticate` result; a stage-1 request without a valid session key returns the error `invalid_session_key`
      # @option options [Hash] :ext (stage 1) an optional Hash of protocol extensions to use (e.g., `{ callbackMethod: 'GET' }`)
      #
      # @option options [String] :challenge (stage 3) a challenge as it was returned by the method after stage 1 call
      # @option options [String] :response (stage 3) a received response, by default delivered as a `response` URL parameter of a GET to the `callbackUrl` (overridable via the `callbackMethod` extension)
      #
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Hash] one of the following shapes:
      #   `{challenge: String, redirectUrl: String}`,
      #   `{signed: true, result: String, issuedAt: Integer, signedAt: Integer, verifiedAt: Integer, verificationResult: Hash}`, or
      #   `{error: {code: String, reason?: String, message: String}}`
      def self.sign(options = nil, config = {})
        return perform('sign', options, config)
      end

      # The `stamp` method may be used to automatically obtain a signature of a given `message` made on behalf of the user with a given `identifier`.
      # Stamps do not typically require any interaction from the user, and may be later verified by any party using the `Triauth.verify` method.
      # They can be used e.g., to prove to other websites that the user is logged in to your website, to authenticate third-party API requests,
      # or in [Diffie–Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) to prove the identities of communicating parties for E2E encryption.
      #
      # > [!WARNING]
      # > Stamps are not single-use proofs. The cryptographic signature covers the `message` together
      # > with the stamp's `type`, `identifier`, `via`, and timestamp — but **not** the challenge nonce,
      # > which is never bound to the signature. A stamp over a fixed `message` thus re-verifies against
      # > any challenge that reuses that `message`, within the `ts` freshness window. Relying parties that
      # > need replay protection must include a fresh, verifier-chosen nonce inside `message` itself.
      #
      # > [!NOTE]
      # > **Get the `stamp` permission and use the same base callbackUrl as for authentication**<br/>
      # > To get the permission, provide the `ext: { permissions: { stamp: true } }` parameter to the `Triauth.authenticate` function during the initial call (i.e., when building the challenge).
      # > The authentication result shows the decision in `ext.permissions`. You can use `stamp` only when the authenticator responds with `ext.dig(:permissions, :stamp) == true`.
      # >
      # > Also, the `callbackUrl` used in this method must have the **same base URL** (its origin plus the path up to and including the last `/`) as the `callbackUrl` from the initial `Triauth.authenticate` call.
      # > For example, if `callbackUrl` used for authentication was `https://example.com/dir1/callback`, the `callbackUrl` used in this method
      # > must sit in that same `https://example.com/dir1/` base directory — only the final path segment may differ, e.g., `https://example.com/dir1/this-callback` (a deeper path such as `https://example.com/dir1/dir2/this-callback` does **not** match the base URL, and the request will be rejected).
      #
      # The stamping is based on the [3-step challenge-response flow](#user-content-3-step-challenge-response-flow):
      #
      # **1. Request**
      #
      # At first, you need to call the `Triauth.stamp` method with the `identifier` option set to the user provided personal identifier (lowercase string),
      # a `callbackUrl` option set to the URL under which your application expects to receive a response (string),
      # a `message` (string) option set to a text message to be stamped,
      # a `sessionKey` (string) option set to the `sessionKey` of a `Triauth.authenticate` result,
      # and an optional `ext` option (Hash) listing the [protocol extensions](#protocol-extensions) that you wish to use.
      #
      # > [!NOTE]
      # > The `message` may consist of letters and digits from any language, space, and a fixed set of punctuation, and is limited to 2 KB.
      # > Emojis, newlines, tabs, and other whitespace or control characters are not allowed.
      # > To stamp binary data or multi-line content (e.g., a public key, a pretty-printed JSON object, a PEM blob),
      # > base64- or hex-encode it before passing it as `message`.
      #
      # In return, you will receive a Hash with the `challenge` (string) and `redirectUrl` (string).
      # You should temporarily store the `challenge` under the user's session, where the user can't tamper with it, and redirect the user's web browser to the `redirectUrl`.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # result = Triauth.stamp({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key, ext: ext })
      # # returns {challenge, redirectUrl} the challenge should be remembered, and user redirected to the redirectUrl
      # # returns {error} on error
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.stamp(
      #   {
      #     identifier: 'john@triauthdemo.org',
      #     callbackUrl: 'https://example.com/triauth-callback',
      #     message: 'login-nonce:4f2d9c715b6e4a3c', # a fresh, single-use nonce from your server, when the stamp gates anything
      #     sessionKey: '59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8'
      #   }
      # )
      # #
      # # {
      # #   challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzdGFtcCIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoic1ZoVXRZOXQzMEVDQjJUR0t2WTktZXpBIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjEsImVrIjoiQkdpOE1kZG11ZnFQdGNncEdwZFFvNDMzSTdxVzVHUm1uU0NmOGZaLVJHclppNng1ZHJNWkZIa3dQZXRkemFyZ21MQ2VvVU9HaF80dXJ6RWt6T3RKU0NrIiwibXNnIjoibG9naW4tbm9uY2U6NGYyZDljNzE1YjZlNGEzYyJ9.osPmHctBwGQUdU346YuJtHPJ-hh01Hia9bxCFZtYhNs',
      # #   redirectUrl: 'https://auth.triauthdemo.org/stamp.html#?skid=wzI1sz3n1R4biw4FL_VJ3Q&request=qKIqh6XTsNbjhjis.huEd1iwa_Xd1q1OhHA7bUmFhfjxCtTEEoPs3l8JSkxJXMrIzBEbjk58CA24JnV6O6LIJ35YTzf3cfjBfBiZyjLdHRbHlpbanM-VTF0Utke_G6Y2Ol3onMk4vmWn40GN6XhyEYRitzXJfCKawNGjhjBoif6r5niNFsOh1f-RCVauYVKUpvSOoVPztSSwYAwtRs9FohwIBG48FpB6kI5xKQLtFJZbhBze0L02gWSwnXwQr5hMh4jOMPV9po7HZUfA1mmRgBkZPhUBSYknBBKYTa1qFadizopi9a9_M7UH1kNTWWEyIXxXt_ibIXhSu1n5-yxVwx2r-M-q7BnH0Nu-V5MDqCnE9fxJ19KoBjj1zpMfZMbx6b2T_zQ7ULPmmZrQKWZYlIDx_XY4f15M_AyZD72i5Awi9JA'
      # # }
      # #
      # ```
      #
      # **2. Redirect**
      #
      # Once the user's web browser is redirected to the `redirectUrl`, the Triauth Authenticator web application immediately responds with the stamp to the `callbackUrl`. This needs a valid session key with the `stamp` permission.
      #
      # **3. Verify**
      #
      # The Triauth Authenticator application redirects the user's web browser to the previously provided `callbackUrl`, by default through the [HTTP GET method](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/GET), and passes a stamp in the `response` URL parameter.
      # The method that is used to pass the response to your application can be configured with [callbackMethod extension](#protocol-extensions).
      #
      # Once you extract the `response` (string), you should pass it to the `Triauth.stamp` function together with the previously stored `challenge` (string) to obtain stamping result.
      # If you decide to also pass the `identifier` and/or `callbackUrl` together with `challenge` and `response`, it will be additionally verified that they are the same as embedded in the `challenge`. Every other option belongs to stage 1 and is rejected here with `invalid_arguments`.
      #
      # Synopsis:
      #
      # ```ruby
      #
      # stamping_result = Triauth.stamp({ challenge: challenge, response: response })
      # # returns {stamped:true, result, issuedAt, signedAt, verifiedAt, verificationResult} upon success
      # # returns {error:{code, message}} upon failure
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.stamp(
      #   {
      #    challenge: 'eyJjYnVybCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdHJpYXV0aC1jYWxsYmFjayIsInR5cGUiOiJzdGFtcCIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoic1ZoVXRZOXQzMEVDQjJUR0t2WTktZXpBIiwiaWF0IjoxNzg3MjI0NzQ4NDQ5LCJ2ZXIiOjEsImVrIjoiQkdpOE1kZG11ZnFQdGNncEdwZFFvNDMzSTdxVzVHUm1uU0NmOGZaLVJHclppNng1ZHJNWkZIa3dQZXRkemFyZ21MQ2VvVU9HaF80dXJ6RWt6T3RKU0NrIiwibXNnIjoibG9naW4tbm9uY2U6NGYyZDljNzE1YjZlNGEzYyJ9.osPmHctBwGQUdU346YuJtHPJ-hh01Hia9bxCFZtYhNs',
      #    response: 'BFpQrxQ6mXjTWkiCFbd1d1QmQdwwdTT56QAffbbiQf_in1BW_nwpZcWqOHgVOV_FnGZuUlFc0bKEZiUBp-SQW2g.dWHtvEeGPf217Qg3SoQ5BBFrytjc5IumJZDwPmGvd4n04pwr7BD8sQQFCGM6WTwc0zu1_nIy9v6_rG4oqtEVyAzVrG7Siepi6AIBwiLgQQqdjcFBX3LNH-Xh6xD_XBOyM4P9QSDJjicL5dg-KUg3P2XXp8J4Tke6F2QK1WyepNxfIY-wi6HeKmsVqTbUYjzj_tJs23jdDv7Ik_7m5CCYkZtq0Xxj8NZSU1BmEw'
      #   }
      # )
      #
      # #
      # # {
      # #   stamped: true,
      # #   result: "|stamp;john@triauthdemo.org;;https://example.com/;v1;1787224751380;;;0lWRFGKZsAC18au2DqtYEavf7zXDkCQH0fTOqwB2QeWsKhSkm29NY0mz1r6VckOVL2utg3wp1QMnySEO56zupg|",
      # #   issuedAt: 1787224748449,
      # #   signedAt: 1787224751380,
      # #   verifiedAt: 1787224751481,
      # #   verificationResult: {
      # #     valid: true,
      # #     type: "stamp",
      # #     identifier: "john@triauthdemo.org",
      # #     identityDomain: "john._at.triauthdemo.org",
      # #     lookupCode: "",
      # #     actor: "",
      # #     actorIdentityDomain: "",
      # #     actorLookupCode: "",
      # #     via: "https://example.com/",
      # #     ver: 1,
      # #     signedAt: 1787224751380,
      # #     verifiedAt: 1787224751481,
      # #     publicProfile: {
      # #       initials: "JD",
      # #       name: "John Doe"
      # #     },
      # #     groups: [],
      # #     deviceName: "desktop",
      # #     deviceTag: "3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ",
      # #     keys: [
      # #       {
      # #         value: "BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8",
      # #         options: {
      # #           type: "es256",
      # #           use: "attest,auth,ping,sign,stamp"
      # #         },
      # #         verified: true,
      # #         skipped: false
      # #       }
      # #     ],
      # #     secure: true,
      # #     expires: 1787226551481,
      # #     signedMetadata: {},
      # #     unsignedMetadata: {}
      # #   }
      # # }
      # #
      # ```
      #
      # > [!IMPORTANT]
      # > Upon successful stamping, the result Hash will have the `stamped` property set to `true`, and the stamp (string) available in the `result` property.
      # > This stamp may also be verified by third parties using the `Triauth.verify` method.
      # >
      # > Upon failed stamping, the `stamped` property will be missing or set to a falsy value, and the `error` property will contain [more details about the encountered problem](#error-codes).
      #
      # @param options [Hash] stamping options. Defaults to nil (a missing argument is rejected with `invalid_arguments`, as the empty Hash is).
      #
      # @option options [String] :identifier (stage 1) the user provided identifier
      # @option options [String] :callbackUrl (stage 1) an application provided URL to which the user's web browser should be redirected with the response
      # @option options [String] :message (stage 1) a text message to be stamped
      # @option options [String] :sessionKey (stage 1, required) the `sessionKey` of a `Triauth.authenticate` result whose `ext.permissions.stamp` is `true`; a stage-1 request without a valid session key returns the error `invalid_session_key`
      # @option options [Hash] :ext (stage 1) an optional Hash of protocol extensions to use (e.g., `{ callbackMethod: 'GET' }`)
      #
      # @option options [String] :challenge (stage 3) a challenge as it was returned by the method after stage 1 call
      # @option options [String] :response (stage 3) a received response, by default delivered as a `response` URL parameter of a GET to the `callbackUrl` (overridable via the `callbackMethod` extension)
      #
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Hash] one of the following shapes:
      #   `{challenge: String, redirectUrl: String}`,
      #   `{stamped: true, result: String, issuedAt: Integer, signedAt: Integer, verifiedAt: Integer, verificationResult: Hash}`, or
      #   `{error: {code: String, reason?: String, message: String}}`
      def self.stamp(options = nil, config = {})
        return perform('stamp', options, config)
      end

      # The verify method verifies triauth signatures and stamps.
      # For the verification to succeed, the public keys associated with the device that made the signature/stamp need to be still present in the DNS.
      #
      # > [!TIP]
      # > For signatures that need to be verifiable even after the respective device keys are removed from the DNS,
      # > consider using a DNS History Service.
      #
      # > [!TIP]
      # > All responses in triauth's 3-step challenge-response protocol are triauth signatures, and to some extent can also be verified later with this method.
      # > But never use this method in place of the original (i.e., never use `Triauth.verify(challenge, response)` in place of `Triauth.authenticate({ challenge: challenge, response: response })` or any other such method),
      # > as it may report `{valid:true}`, even when important constraints are not met (e.g., the authentication request has timed out).
      #
      # > [!IMPORTANT]
      # > By default `Triauth.verify` accepts only a **single-signature** envelope (`maxSignatures` defaults to 1).
      # > To verify a multi-signature envelope (e.g. an attestation bundle), raise `maxSignatures` to the number of
      # > segments you expect; otherwise a multi-segment envelope is reported as `{valid:false, reason:'declined'}`.
      #
      # Synopsis:
      #
      # ```ruby
      # verification_result = Triauth.verify(message, signature)
      # # returns {valid:true, type, identifier, identityDomain, lookupCode, actor, actorIdentityDomain, actorLookupCode, via, ver, signedAt, verifiedAt, publicProfile, groups, deviceName, deviceTag, keys, secure, expires, signedMetadata, unsignedMetadata} if signature has been successfully verified
      # # returns {valid:true, type:'multisig', secure, expires, verifiedAt, signatures} when a multi-signature was verified, the signatures array carries the individual verification results
      # # returns {valid:false, reason} when the envelope was evaluated and not accepted; reason is one of 'malformed' (unparseable envelope), 'invalid' (bad crypto, an unresolvable signer, or an identifier/actor/type/ver/via mismatch), 'expired' (signature timestamp outside notBefore/notAfter), or 'declined' (segment count outside minSignatures/maxSignatures)
      # # returns {error} when the signature could not be evaluated at all (e.g. bad arguments, DNS failure, or a requireSecure veto)
      #
      # ```
      #
      # > [!IMPORTANT]
      # > Accept a signature only when `valid == true`. Treat every other result as not verified. The `reason` string on a `{valid:false}` result is diagnostic only (for logging / UX / retry classification) - never use it as an accept/reject signal.
      # > If you raise `maxSignatures`, expect that you may get `type:'multisig'` back without a top-level `identifier` set.
      #
      # Example:
      #
      # ```ruby
      # Triauth.verify(
      #   'login-nonce:4f2d9c715b6e4a3c',
      #   '|stamp;john@triauthdemo.org;;https://example.com/;v1;1787224751380;;;0lWRFGKZsAC18au2DqtYEavf7zXDkCQH0fTOqwB2QeWsKhSkm29NY0mz1r6VckOVL2utg3wp1QMnySEO56zupg|'
      # )
      # #
      # # {
      # #   valid: true,
      # #   type: "stamp",
      # #   identifier: "john@triauthdemo.org",
      # #   identityDomain: "john._at.triauthdemo.org",
      # #   lookupCode: "",
      # #   actor: "",
      # #   actorIdentityDomain: "",
      # #   actorLookupCode: "",
      # #   via: "https://example.com/",
      # #   ver: 1,
      # #   signedAt: 1787224751380,
      # #   verifiedAt: 1787224808550,
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
      # #   secure: true,
      # #   expires: 1787226608550,
      # #   signedMetadata: {},
      # #   unsignedMetadata: {}
      # # }
      # #
      # ```
      #
      # @param message [String] A message that was signed. Defaults to nil (a missing argument is rejected with `invalid_arguments`).
      # @param signature [String] The received signature of the message. Defaults to nil (a missing argument is rejected with `invalid_arguments`).
      # @param constraints [Hash] Optional additional constraints that should be verified prior to calling the time-taking internal crypto functions. Defaults to `{}`.
      # @option constraints [String] :identifier identifier on behalf of which the signature was generated
      # @option constraints [String] :actor the actor (delegate) whose keys made the signature on behalf of the `identifier`; `''` requires a non-delegated signature
      # @option constraints [Integer] :ver the triauth signature envelope version to require
      # @option constraints [String] :type the type of signature to require — one of 'attest'|'auth'|'ping'|'sign'|'stamp'. Pin this to the expected signature type when possible.
      # @option constraints [String] :via the base URL (e.g., https://example.com/) of the client application the signature was issued to (the base URL of its `callbackUrl`). Pin it when possible. Otherwise a signature requested by another application verifies just as well.
      # @option constraints [Integer] :notBefore a Unix timestamp in milliseconds (a non-number or `NaN` gives `{valid:false, reason:'invalid'}`). If the timestamp encoded in the signature is earlier than this value, the result is `{valid:false, reason:'expired'}`. Note: unlike the internal verify path used by `authenticate`/`ping`/`sign`/`stamp`, `Triauth.verify` does **not** widen this bound by `config[:maximalAllowedClientClockDrift]` - the comparison is strict.
      # @option constraints [Integer] :notAfter a Unix timestamp in milliseconds (a non-number or `NaN` gives `{valid:false, reason:'invalid'}`). If the timestamp encoded in the signature is greater than this value, the result is `{valid:false, reason:'expired'}`. Note: strict comparison; no clock-drift slack is applied (see `notBefore`).
      # @option constraints [Integer] :minSignatures the minimum number of signature segments the (multi-)signature envelope must contain. A count below this is a signature-count policy decline, reported as `{valid:false, reason:'declined'}`. Note: this counts segments, NOT distinct signers - the same identity may legitimately contribute multiple (e.g., per-device) signatures; to require distinct signers, additionally check `signatures[].identifier` and/or `signatures[].deviceTag` in the result. Because `maxSignatures` defaults to 1, requiring more than one signature means you must also raise `maxSignatures`.
      # @option constraints [Integer] :maxSignatures the maximum number of signature segments the (multi-)signature envelope may contain. **Defaults to 1** (secure-by-default): when omitted, `Triauth.verify` accepts only a single signature, so a multi-segment envelope is reported as `{valid:false, reason:'declined'}`. To verify a multi-signature envelope, pass an explicit `maxSignatures` (>= the number of segments you expect). The default of 1 also pins the result to the flat single-signature shape and bounds the per-segment DNS resolution work for untrusted input.
      # @param config [Hash] optional overrides for the global Triauth.config settings. Defaults to `{}`. When `config[:requireSecure]` is set, an otherwise-valid signature whose DNS chain was not reported DNSSEC-validated (`secure != true`) is rejected with the error `dnssec_required` (surfaced as `{error}`).
      #
      # @return [Hash] one of the following shapes:
      #   `{valid: true, type: String, identifier: String, identityDomain: String, lookupCode: String, actor: String, actorIdentityDomain: String, actorLookupCode: String, via: String, ver: Integer, signedAt: Integer, verifiedAt: Integer, publicProfile: Hash, groups: Array<String>, deviceName: String, deviceTag: String, keys: Array<Hash>, secure: Boolean, expires: (Integer, nil), signedMetadata: Hash, unsignedMetadata: Hash}`,
      #   `{valid: true, type: 'multisig', secure: Boolean, expires: (Integer, nil), verifiedAt: Integer, signatures: Array<Hash>}`,
      #   `{valid: false, reason: 'malformed'|'invalid'|'expired'|'declined'}`, or
      #   `{error: {code: String, reason?: String, message: String}}`
      def self.verify(message = nil, signature = nil, constraints = {}, config = {})
        config = Helpers.merge_config(config)
        config[:logger] = (config[:logger].respond_to?(:spawn) ? config[:logger].spawn(config[:cid]) : nil) || config[:logger]

        Helpers.log(config, :info, 'Processing Triauth.verify')
        ts = Helpers.now

        begin
          # Check the sanity of received arguments
          # (`typeof constraints !== 'object'` admits null and Arrays, which `hasOnlyKnownProperties` then rejects, so "not a Hash" is the
          # same accept-set; `typeof config !== 'object'` can never fire after `mergeConfig` in either language)
          if !Helpers.is_string(message) || !Helpers.is_string(signature) || !constraints.is_a?(Hash) ||
             !Helpers.has_only_known_properties(constraints, %i[identifier actor ver type via notBefore notAfter minSignatures maxSignatures])
            raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Invalid or missing function arguments' })
          end

          # Reject config overrides carrying unknown keys
          if !Helpers.has_only_known_properties(config, Triauth::KNOWN_CONFIG_KEYS)
            raise Triauth::Error.new({ code: 'invalid_config', message: 'Unrecognized configuration key' })
          end

          # Signature-count bounds, when provided, must be numbers
          min = constraints[:minSignatures]
          max = constraints[:maxSignatures]
          if (!min.nil? && (!Helpers.is_number(min) || (min.is_a?(Float) && min.nan?))) ||
             (!max.nil? && (!Helpers.is_number(max) || (max.is_a?(Float) && max.nan?)))
            raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Invalid or missing function arguments' })
          end

          # Secure-by-default: when the caller does not specify maxSignatures, it defaults to 1, so an
          # un-opted-in multi-signature envelope is declined below.
          if constraints[:maxSignatures].nil?
            constraints = Helpers.object_assign({}, constraints, { maxSignatures: 1 })
          end

          sig = MultiSignature.new(signature, config)

          # A signature-count policy mismatch means we DECLINE cryptographic verification and report `{valid:false, reason:'declined'}`
          seg_count = sig.signatures.length
          min_signatures = constraints[:minSignatures]
          max_signatures = constraints[:maxSignatures]
          if (!max_signatures.nil? && seg_count > max_signatures) ||
             (!min_signatures.nil? && seg_count < min_signatures)
            Helpers.log(config, :info, 'Verification declined - signature count outside minSignatures/maxSignatures policy', { segCount: seg_count, minSignatures: min_signatures, maxSignatures: max_signatures })
            return { valid: false, reason: 'declined' }
          end

          verify_result = sig.verify(message, constraints)

          if !verify_result || !verify_result[:valid]
            Helpers.log(config, :info, 'Verification failed')

            # `null` => time-related failure ("expired"); `false` (or a defensive object with valid:false)
            # => any other failure ("invalid"). Preserves the 3-state verdict the lower layers compute.
            return { valid: false, reason: verify_result.nil? ? 'expired' : 'invalid' }
          end

          # Enforce config.requireSecure (mirrors the challenge-response flows and Triauth.check): an
          # otherwise-valid envelope whose DNS chain was not reported DNSSEC-validated is rejected with
          # the error dnssec_required, surfaced as {error} via the catch below.
          ChallengeResponseFlow.assert_secure(verify_result[:secure], config)

          Helpers.log(config, :info, 'Verification successful')

          retval = Helpers.clone(verify_result[:signatures].length > 1 ? verify_result : verify_result[:signatures][0])

          return retval
        rescue StandardError => err
          # A validation/parse error (one that carries a reason) means the envelope could not be parsed into a well-formed
          # signature - a definitive negative verdict reported as {valid:false, reason:'malformed'}. Other
          # TriauthErrors (e.g. dnssec_required from requireSecure, or a dns_unavailable DNS failure) surface as {error}.
          if err.is_a?(Triauth::Error) && !err.reason.nil?
            return { valid: false, reason: 'malformed' }
          end

          return Triauth::Error.process(err, config)
        ensure
          Helpers.log(config, :info, "Completed in #{(Helpers.now - ts).round}ms")
        end
      end
    end
  end
end
