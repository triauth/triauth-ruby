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
require_relative 'multi_signature'

module Triauth
  # Represents an authentication response that is sent from Triauth Authenticator back to the client application,
  # typically in a response to the previously sent Triauth::Challenge.
  class Response
    # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
    attr_reader :config
    # @return [String] The received response - a triauth multi-signature envelope, as given to the constructor.
    attr_reader :response_string

    # Constructs a new instance of Response around a response received from the Triauth Authenticator.
    #
    # @param response_string [String] The received response - a triauth multi-signature envelope. It is
    #   parsed and validated by `verify`, not by this constructor.
    # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
    def initialize(response_string, config = {})
      @config = Helpers.merge_config(config)
      @response_string = response_string # response_string is a triauth signature (string)
    end

    # Verifies that the signatures provided as a part of this authentication response are valid for the given challenge.
    #
    # @param type [String] Expected type of the response, one of 'attest', 'auth', 'ping', 'sign', 'stamp'.
    # @param signed_payload [String] The exact string that the cryptographic signature is verified against.
    #   For 'auth' and 'ping' this is the serialized challenge string; for 'sign'
    #   and 'stamp' it is the human-readable `msg`; for 'attest' it is the
    #   base64url-encoded SHA-256 digest of the challenge string. Callers must
    #   pass it explicitly — there is no implicit default.
    # @param challenge [Triauth::Challenge] The Challenge originally built and sent to the Triauth Authenticator.
    #   Used only for constraint checks (identifier match, `iat` bounds); it is
    #   not the cryptographic input to verification.
    # @param constraints [Hash] Optional constraints that the response must satisfy. Defaults to `{}`.
    # @option constraints [String] :identifier If given, must match the identifier embedded in the challenge.
    # @option constraints [Integer] :notBefore If given, the challenge `iat` and the signature timestamp must be >= this timestamp. The check allows for clock drift.
    # @option constraints [Integer] :notAfter If given, the challenge `iat` and the signature timestamp must be <= this timestamp. The check allows for clock drift.
    # @option constraints [Integer] :minSignatures If given, the multi-signature envelope must contain at least this many signatures.
    # @option constraints [Integer] :maxSignatures If given, the multi-signature envelope must contain at most this many signatures.
    #
    # @return [Hash, nil, false] `{type: String, valid: Boolean, secure: Boolean, expires: (Integer, nil), verifiedAt: (Integer, nil), signatures: Array<Hash>}`, nil or false:
    #   - `nil` when a time-related constraint fails (signal to surface as "expired" to the user),
    #   - `false` when any other verification fails,
    #   - or a Hash with: `valid:true`, the `type` of the envelope ('multisig'), a `secure` flag
    #     (true only when DNSSEC was validated for every contributing signature's identity),
    #     an `expires` timestamp (the earliest defined per-signature expiry, or nil if none of
    #     the contributing key groups had a TTL), a `verifiedAt` timestamp (the latest per-signature
    #     verification time - when the whole envelope finished verifying), and a `signatures` array of
    #     per-signature results (each carrying its own `identifier`, `identityDomain`, `lookupCode`, `actor`, `actorIdentityDomain`, `actorLookupCode`, `publicProfile`,
    #     `groups`, `keys`, `deviceName`, `deviceTag`, `signedAt`, `verifiedAt`, `signedMetadata`, `unsignedMetadata`).
    #
    # @raise [Triauth::Error] `invalid_signature` when the response is not a well-formed multi-signature envelope (raised while
    #   parsing it, after the constraint checks), and `dns_unavailable` when DNS resolution of a signer's identity fails.
    def verify(type, signed_payload, challenge, constraints = {})
      ####
      # Constraints - Verify constraints in relation to the restored authentication request
      #
      # The challenge `iat` was minted by the integrator's own infrastructure, but not necessarily
      # by this host - under load balancing, stage 1 and stage 3 may land on different servers with
      # imperfectly synchronized clocks. The `iat` bounds are therefore widened by the (small)
      # `maximalAllowedServerClockDrift`, while signature timestamps minted on the end-user's device
      # get the (larger) `maximalAllowedClientClockDrift` below.

      if !Helpers.has_only_known_properties(constraints, %i[identifier notBefore notAfter minSignatures maxSignatures])
        Helpers.log(@config, :error, 'Unrecognized constraint')
        return false
      end

      if !constraints[:identifier].nil? &&
         challenge.identity.identifier != constraints[:identifier]
        Helpers.log(@config, :debug, 'constraints.identifier not satisfied')
        return false
      end

      # Fail closed if time bounds are provided in a non-numeric form rather than silently
      # coercing to NaN (which would compare as false and bypass the window check).
      if (!constraints[:notBefore].nil? && (!Helpers.is_number(constraints[:notBefore]) || (constraints[:notBefore].is_a?(Float) && constraints[:notBefore].nan?))) ||
         (!constraints[:notAfter].nil? && (!Helpers.is_number(constraints[:notAfter]) || (constraints[:notAfter].is_a?(Float) && constraints[:notAfter].nan?)))
        Helpers.log(@config, :error, 'Invalid notBefore/notAfter constraint')
        return false
      end

      if !constraints[:notBefore].nil? &&
         (!Helpers.is_number(challenge.data[:iat]) || challenge.data[:iat] < constraints[:notBefore] - @config[:maximalAllowedServerClockDrift])
        Helpers.log(@config, :debug, 'constraints.notBefore not satisfied')
        return nil
      end

      if !constraints[:notAfter].nil? &&
         (!Helpers.is_number(challenge.data[:iat]) || challenge.data[:iat] > constraints[:notAfter] + @config[:maximalAllowedServerClockDrift])
        Helpers.log(@config, :debug, 'constraints.notAfter not satisfied')
        return nil
      end

      ####
      # Signature - Verify the triauth signature passed in response

      signature = MultiSignature.new(@response_string, @config)

      # The JS literal carries `undefined` members for the absent constraints; the nil members here take the same `!= null` branches in `MultiSignature#verify`.
      retval = signature.verify(
        signed_payload,
        {
          type: type,
          identifier: constraints[:identifier],
          notBefore: constraints[:notBefore].nil? ? nil : constraints[:notBefore] - @config[:maximalAllowedClientClockDrift],
          notAfter: constraints[:notAfter].nil? ? nil : constraints[:notAfter] + @config[:maximalAllowedClientClockDrift],
          minSignatures: constraints[:minSignatures],
          maxSignatures: constraints[:maxSignatures]
        }
      )

      if !retval || !retval[:valid]
        Helpers.log(@config, :debug, 'Triauth.Response.verify failed')
        return retval.nil? ? nil : false
      end

      Helpers.log(@config, :debug, 'Triauth.Response.verify successful', { retval: retval })

      return retval
    end
  end
end
