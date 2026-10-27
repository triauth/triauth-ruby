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
require_relative 'helpers'
require_relative 'validator'
require_relative 'identity'
require_relative 'challenge'
require_relative 'response'
require_relative 'response_cipher'
require_relative 'request_cipher'
require_relative 'authentication_endpoint'
require_relative 'config'

module Triauth
  # Internal helper that implements the shared 3-step challenge-response flow used by
  # some of the top-level API methods (e.g., `authenticate`).
  #
  # Each API method delegates to `perform()` with a flow `type` and a pair of callbacks
  # (`onChallenge`, `onResponse`) carrying the per-flow logic.
  class ChallengeResponseFlow
    # Executes one stage of the challenge-response flow:
    #  - **Stage 1** (when `identifier`+`callbackUrl` are given, `challenge`/`response` are not): builds a challenge
    #    that carries a fresh encryption key (`ek`), invokes `onChallenge` to let the caller mutate `challenge.data`,
    #    then returns `{challenge, redirectUrl}`. The returned `challenge` is `<challenge>.<decryptionKey>`.
    #  - **Stage 3** (when `challenge`+`response` are given): parses both, opens the sealed response with the
    #    decryption key of the stored challenge, sanity-checks them against optional `identifier`/`callbackUrl`
    #    constraints, then invokes `onResponse` for per-flow verification.
    #
    # @param type [String] Flow type: `'auth'`, `'ping'`, `'attest'`, `'sign'`, or `'stamp'`.
    # @param options [Hash] User-facing options. Stage 1 expects `{identifier, callbackUrl, ext?, sessionKey?}`
    #   plus the flow's own options (`sessionKey` is required for every flow except `'auth'`,
    #   where it is rejected). Stage 3 expects `{challenge, response, identifier?, callbackUrl?}`
    #   (the optional ones, if provided, are additionally checked against the values embedded
    #   in the challenge) and rejects every other option as unrecognized. Defaults to `{}`.
    # @param callbacks [Hash{Symbol => Proc}] `{onChallenge: Proc, onResponse: Proc}` -
    #   `onChallenge.call({challenge: challenge})` runs after the `Triauth::Challenge` is built (stage 1), giving the caller
    #   a chance to populate `challenge.data` (e.g., `msg`, `attest`, `attachments`).
    #   `onResponse.call({challenge: challenge, response: response, sessionKey: session_key})` performs verification (stage 3); must return the per-flow
    #   success object, `nil` for expired-style failures, or `false` for generic verification failures.
    #   `sessionKey` is the session key from opening the sealed response (see `ResponseCipher.open`).
    # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
    # @param flow_options [Array<Symbol>] Names of the flow's own stage-1 options (e.g., `:message`), which `onChallenge`
    #   reads from `options` and which stage 3 rejects like any unrecognized option. Defaults to `[]`.
    #
    # @return [Hash] `{challenge: String, redirectUrl: String}` (stage 1), whatever `onResponse` returned
    #   (stage 3 success), or `{error: {code: String, reason: String (optional), message: String}}` if any error was caught. When
    #   `config[:requireSecure]` is set, a stage-3 result that is not DNSSEC-secure is rejected with
    #   `{error: {code: 'dnssec_required', …}}` instead of being returned (see `assert_secure`).
    def self.perform(type, options = {}, callbacks = { onChallenge: nil, onResponse: nil }, config = {}, flow_options = [])
      Helpers.log(config, :info, "Processing Triauth.#{type}")
      ts = Helpers.now

      begin
        # Ensure only recognized options are present to help avoid misspellings. Stage 3 reads the challenge and the
        # response, and cross-checks an identifier and a callbackUrl against the challenge. Every other option shapes
        # the challenge at stage 1: `ext`, the flow's own options, and `sessionKey` for the flows that follow a sign-in
        # (ping/attest/sign/stamp), not for auth.
        stage3 = options.is_a?(Hash) && !options[:challenge].nil? && !options[:response].nil? # `options !== null && typeof options === 'object'`: a Hash (an Array has no `challenge` member on either side)
        allowed_options = if stage3 # the JS ternary nests a second one for `sessionKey`: an `if` expression (RuboCop `Style/NestedTernaryOperator`)
                            %i[challenge response identifier callbackUrl]
                          else
                            [:identifier, :callbackUrl, :challenge, :response, :ext, *flow_options, *(type != 'auth' ? [:sessionKey] : [])]
                          end

        if !Helpers.has_only_known_properties(options, allowed_options)
          raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Unrecognized function argument' })
        end

        # Reject config overrides carrying unknown keys (typos that would otherwise be silently ignored,
        # sometimes weakening security - e.g. a misspelled `requireSecure`). We validate the MERGED config,
        # so a stray key is caught whether it came from this call's override or a global Triauth.config
        if !Helpers.has_only_known_properties(config, Triauth::KNOWN_CONFIG_KEYS)
          raise Triauth::Error.new({ code: 'invalid_config', message: 'Unrecognized configuration key' })
        end

        # Read supported options
        identifier = options[:identifier]
        callback_url = options[:callbackUrl]
        challenge = options[:challenge]
        response = options[:response]
        ext = options[:ext]
        session_key = options[:sessionKey]

        # Stage 1 - identifier, callbackUrl, and ext (optional) are provided, and we need to build and return a challenge and redirectUrl
        if !identifier.nil? &&
           !callback_url.nil? &&
           challenge.nil? && response.nil?
          validation_error =
            Validator.validate_identifier(identifier)[:errors][0] ||
            Validator.validate_callback_url(callback_url)[:errors][0] ||
            (!ext.nil? && Validator.validate_ext(ext)[:errors][0]) ||
            (!session_key.nil? && Validator.validate_session_key(session_key)[:errors][0])

          if validation_error
            raise Triauth::Error.new(validation_error)
          end

          # Every flow that follows a sign-in (all but `auth`) requires the session key of that sign-in
          if type != 'auth' && session_key.nil?
            raise Triauth::Error.new({ code: 'invalid_session_key', reason: 'invalid', message: 'Invalid session key' })
          end

          Helpers.log(config, :info, 'Request parameters:', { identifier: identifier, callbackUrl: callback_url, ext: ext })

          identity = Identity.new(identifier, {}, config)

          # Prepare options for the authentication request
          challenge_options = {}

          challenge_options[:cburl] = callback_url

          if !ext.nil?
            challenge_options[:ext] = ext
          end

          # Build the authentication request for the given identity with the given options - `callbackUrl` and `ext`.
          challenge_obj = Challenge.build(type, identity, challenge_options, config)

          # The authenticator seals the response to `ek`. The decryption key stays with the stored challenge.
          pair = ResponseCipher.generate_key_pair
          encryption_key = pair[:encryptionKey]
          decryption_key = pair[:decryptionKey]
          challenge_obj.data[:ek] = encryption_key

          callbacks[:onChallenge].call({ challenge: challenge_obj })
          challenge_string = challenge_obj.to_s

          # Fail early if the just-built challenge is not itself a valid challenge
          challenge_error = Validator.validate_challenge(challenge_string)[:errors][0]
          if challenge_error
            raise Triauth::Error.new(challenge_error)
          end

          # A delegated session key is `<domain>:<key>`, and its session is at the authenticator of that domain
          # (`sessionKey?.includes(':')`: nil, or a validated key of one or two parts; `sessionKeyDomain ?`: the empty string is the only falsy value it can hold)
          session_key_domain, session_key_secret = !session_key.nil? && session_key.include?(':') ? session_key.split(':', -1) : ['', session_key]
          authentication_endpoint = session_key_domain != '' ? AuthenticationEndpoint.new(session_key_domain, config) : identity.authentication_endpoint

          # Check if authentication endpoint has been configured for the domain name
          if !authentication_endpoint.resolve
            raise Triauth::Error.new({ code: 'domain_not_configured', message: 'Domain is not configured for triauth' })
          end

          # Enforce config.requireSecure if set
          ChallengeResponseFlow.assert_secure(authentication_endpoint.secure, config)

          # A request that follows a sign-in travels sealed under the session key, with `skid` to find the key.
          # A sign-in has no session key yet, so its challenge travels readable.
          # (`sessionKey ?`: nil, or a validated non-empty string)
          redirect_url_params = !session_key.nil? ? { skid: RequestCipher.skid(session_key_secret), request: RequestCipher.seal(session_key_secret, challenge_string) } : { challenge: challenge_string }

          redirect_url = authentication_endpoint.url_for(type, redirect_url_params)
          redirect_url_string = redirect_url.to_s

          # Return the challenge that the client should remember (with the key that opens the response), and a redirectUrl
          # to which the user's web browser should be redirected.
          return Helpers.clone({ challenge: "#{challenge_string}.#{decryption_key}", redirectUrl: redirect_url_string })

        # Stage 3 - both challenge and response are provided, and we need to verify them against each other and return the result.
        elsif !challenge.nil? &&
              !response.nil?

          if response == 'false'
            raise Triauth::Error.new({ code: 'request_denied', message: 'Request has been denied' })
          end

          # The stored challenge is `<challenge>.<decryptionKey>`, and the response is sealed to the challenge's `ek`
          # (`typeof challenge === 'string' ? challenge.split('.') : []`: JS splits `''` into `['']` where Ruby gives `[]`)
          challenge_string, decryption_key, rest = if Helpers.is_string(challenge)
                                                     challenge.empty? ? [''] : challenge.split('.', -1)
                                                   else
                                                     []
                                                   end

          validation_error =
            Validator.validate_challenge(challenge_string)[:errors][0] ||
            ((!rest.nil? || !Helpers.is_base64url_string(decryption_key) || decryption_key.length != 43) && { code: 'invalid_challenge', reason: 'invalid', message: 'Invalid challenge' }) || # the `&&` yields the Hash or false, falling through as in JS; `.length` is only reached on a base64url String
            Validator.validate_sealed_response(response)[:errors][0] ||
            (!identifier.nil? && Validator.validate_identifier(identifier)[:errors][0]) ||
            (!callback_url.nil? && Validator.validate_callback_url(callback_url)[:errors][0])

          if validation_error
            raise Triauth::Error.new(validation_error)
          end

          Helpers.log(config, :info, 'Verifying response with constraints', { type: type, identifier: identifier, callbackUrl: callback_url })

          # Parse the received response (string) into the Triauth.Response object.
          challenge_obj = nil

          begin
            challenge_obj = Challenge.from_string(challenge_string, config)
          rescue StandardError => err
            raise Triauth::Error.new({ code: 'invalid_challenge', reason: 'invalid', message: 'Invalid challenge' }, { cause: err })
          end

          # Every challenge carries the encryption key that its response is sealed to
          encryption_key = challenge_obj.data[:ek]
          if !Helpers.is_base64url_string(encryption_key) || encryption_key.length != 87
            raise Triauth::Error.new({ code: 'invalid_challenge', reason: 'invalid', message: 'Invalid challenge' })
          end

          # `let envelope, sessionKey;`: the JS `sessionKey` is a new binding of this block, shadowing the stage-1 `const`; here it re-assigns the same local, which stage 3 never reads otherwise
          envelope = nil
          session_key = nil

          begin
            opened = ResponseCipher.open(encryption_key, decryption_key, response)
            envelope = opened[:response]
            session_key = opened[:sessionKey]
          rescue StandardError => err
            raise Triauth::Error.new({ code: 'invalid_response', reason: 'invalid', message: 'Invalid response' }, { cause: err })
          end

          response_error = Validator.validate_response(envelope)[:errors][0]
          if response_error
            raise Triauth::Error.new(response_error)
          end

          response_obj = Response.new(envelope, config)

          # Make sure the challenge's type matches the flow type, and (if again passed in options)
          # that the identifier and/or callbackUrl matches the one embedded in the challenge.
          if challenge_obj.data[:type] != type ||
             (!identifier.nil? && challenge_obj.identity.identifier != identifier) ||
             (!callback_url.nil? && challenge_obj.data[:cburl] != callback_url)
            raise Triauth::Error.new({ code: 'verification_failed', message: 'Your identity could not be verified' })
          end

          retval = callbacks[:onResponse].call({ challenge: challenge_obj, response: response_obj, sessionKey: session_key })

          # `if (retval)`: the per-flow success Hash is truthy, the `nil` and `false` of the three-state contract are not
          if retval
            # Enforce config.requireSecure if set
            ChallengeResponseFlow.assert_secure(retval[:secure].nil? ? retval[:verificationResult]&.[](:secure) : retval[:secure], config)
            return retval

          elsif retval.nil?
            raise Triauth::Error.new({ code: 'request_expired', message: 'Authentication request has expired, please try again' })

          else
            raise Triauth::Error.new({ code: 'verification_failed', message: 'Your identity could not be verified' })

          end

        # Fail when the given function arguments do not match to any of stages.
        else
          raise Triauth::Error.new({ code: 'invalid_arguments', message: 'Invalid or missing function arguments - expected either {identifier,callbackUrl,ext,...} or {challenge,response,identifier?,callbackUrl?}' })

        end
      rescue StandardError => err
        return Triauth::Error.process(err, config)
      ensure
        Helpers.log(config, :info, "Completed in #{(Helpers.now - ts).round}ms")
      end
    end

    # Verifies a single-signature challenge response and enforces the success invariant shared by the
    # `auth`, `ping`, `sign`, and `stamp` flows: the envelope must carry exactly one signature, that
    # signature must be valid and backed by at least one key, its identifier must match the one bound
    # in the challenge, and the challenge's `cburl` must be a valid callback URL whose base URL equals
    # the signature's `via`. (The multi-signature `attest` flow has a different shape - 1 user + N
    # attester signatures - and intentionally does NOT use this helper.)
    #
    # @param type [String] flow type ('auth'|'ping'|'sign'|'stamp'), passed through to Response#verify.
    # @param signed_payload [String] the exact bytes the signature is verified against (the serialized
    #   challenge for auth/ping; the human-readable `msg` for sign/stamp).
    # @param challenge [Triauth::Challenge] the re-hydrated challenge.
    # @param response [Triauth::Response] the parsed response envelope.
    # @param timeout [Integer] the flow's freshness window (e.g., `config[:authTimeout]`), subtracted from now.
    # @param config [Hash] effective config (with an already-spawned logger).
    #
    # @return [Hash, nil, false] On success, `{sig: Hash, verifyResult: Hash}` - the verified first
    #   signature plus the full multi-signature result (callers read `secure`/`expires` from the
    #   latter); `nil` on a time/expiry failure; `false` on any other verification failure.
    def self.verify_challenge_response(type, signed_payload, challenge, response, timeout, config)
      verify_result = response.verify(
        type,
        signed_payload,
        challenge,
        {
          identifier: challenge.identity.identifier,
          notBefore: Helpers.date_now - (timeout.nil? || timeout == 0 ? 0 : timeout), # `timeout || 0`: the JS falsy set of a number, nil and 0
          notAfter: Helpers.date_now,
          minSignatures: 1,
          maxSignatures: 1
        }
      )

      sig = verify_result && verify_result[:signatures][0]

      if verify_result && verify_result[:valid] && verify_result[:signatures].length == 1 &&
         sig && sig[:valid] && sig[:keys].length > 0 &&
         sig[:identifier] == challenge.identity.identifier &&
         Validator.validate_callback_url(challenge.data[:cburl])[:valid] && Helpers.get_base_url(challenge.data[:cburl]) == sig[:via]
        return { sig: sig, verifyResult: verify_result }

      # For time constraints verification failure, signal "expired" (caller surfaces request_expired).
      elsif verify_result.nil?
        # `parseInt(challenge.data.iat, 10)` of a number: a non-number (or a non-finite one) logs `NaN` there and nil here - log data only
        Helpers.log(config, :info, 'Verification failed - request expired', { identifier: challenge.identity.identifier, iat: Helpers.is_number(challenge.data[:iat]) && challenge.data[:iat].finite? ? challenge.data[:iat].to_i : nil })
        return nil

      # For other falsy signature verification results, signal a generic failure (caller surfaces verification_failed).
      else
        Helpers.log(config, :info, 'Verification failed', { identifier: challenge.identity.identifier })
        return false

      end
    end

    # Enforces the optional `config.requireSecure` policy: when the caller has opted in, an
    # otherwise-valid result whose DNS chain was not reported DNSSEC-validated (`secure !== true`)
    # is rejected.
    #
    # @param secure [Boolean, nil] the aggregate DNSSEC-validation flag of the result.
    # @param config [Hash] effective config; `requireSecure` (default false) toggles enforcement.
    # @raise [Triauth::Error] `dnssec_required` when `config[:requireSecure]` is set and `secure` is not strictly `true`.
    def self.assert_secure(secure, config)
      # `if (config.requireSecure && ...)`: the JS falsy set of a caller value (nil, false, 0 and '') spelled out
      require_secure = config[:requireSecure]
      if !(require_secure.nil? || require_secure == false || require_secure == 0 || require_secure == '') && secure != true
        raise Triauth::Error.new({ code: 'dnssec_required', message: 'Your domain does not support DNSSEC, which is required to continue.' })
      end
    end
  end
end
