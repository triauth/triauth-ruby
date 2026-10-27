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
require_relative 'protocol'
require_relative 'signature'

module Triauth
  # A multi-signature envelope, which is one or more `Triauth::Signature` segments joined and wrapped by the `|` character.
  class MultiSignature
    # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
    attr_reader :config
    # @return [String] The multi-signature envelope this instance was parsed from.
    attr_reader :raw_data
    # @return [Array<Triauth::Signature>] The signature segments the envelope carries, in their order.
    attr_reader :signatures

    # Concatenates individual signature envelopes into one multi-signature envelope.
    #
    # @param signatures [Array<String>] Individual `Triauth::Signature` envelopes, each wrapped in `|`.
    #
    # @return [String] the multi-signature envelope carrying the given signatures, in the given order.
    def self.generate(*signatures)
      return Protocol::WRAPPER + signatures.map { |s| s[1...-1] }.join(Protocol::WRAPPER) + Protocol::WRAPPER
    end

    # Parses a multi-signature envelope into the individual `Triauth::Signature` segments it carries.
    #
    # @param raw_data [String] A multi-signature envelope: one or more signature segments wrapped in,
    #   and delimited by, the `|` character.
    # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
    #
    # @raise [Triauth::Error] `invalid_signature` when the envelope is not a string, is not `|`-wrapped, exceeds
    #   `LIMITS[:signatureBytesize]`, carries more than `LIMITS[:maxMultiSignatures]`
    #   segments, or repeats a byte-identical segment.
    def initialize(raw_data, config = {})
      @config = Helpers.merge_config(config)

      # Check the basic sanity and format of received arguments
      if !Helpers.is_string(raw_data) ||
         raw_data.length <= 3 ||
         (raw_data[0] != Protocol::WRAPPER || raw_data[-1] != Protocol::WRAPPER) ||
         Helpers.byte_size(raw_data) > Protocol::LIMITS[:signatureBytesize]
        raise Triauth::Error.new({ code: 'invalid_signature', reason: 'invalid', message: 'Invalid signature' })
      end

      @raw_data = raw_data

      segments = raw_data[1...-1].split(Protocol::WRAPPER, -1)

      max_multi_signatures = Protocol::LIMITS[:maxMultiSignatures]
      if segments.length < 1 || segments.length > max_multi_signatures
        raise Triauth::Error.new({ code: 'invalid_signature', reason: 'invalid', message: 'Invalid signature' })
      end

      # Do not allow byte-identical duplicate segments
      if segments.uniq.length != segments.length
        raise Triauth::Error.new({ code: 'invalid_signature', reason: 'invalid', message: 'Invalid signature' })
      end

      # Extract and parse signature segments
      @signatures = segments.map { |sig| Signature.new(Protocol::WRAPPER + sig + Protocol::WRAPPER, config) }
    end

    # Verifies that the signature is valid for the given message.
    #
    # @param message [String] Message, should be the same as originally signed.
    # @param constraints [Hash] Optional constraints that the signature must satisfy. Defaults to `{}`.
    # @option constraints [String] :type If given, passed through to each contributing `Signature#verify` for type matching.
    # @option constraints [String] :identifier If given, must match the identifier for which it was created.
    # @option constraints [String] :actor If given, passed through to each contributing `Signature#verify` for actor matching ('' = no actor).
    # @option constraints [Integer] :ver If given, passed through to each contributing `Signature#verify` for version matching.
    # @option constraints [String] :via If given, passed through to each contributing `Signature#verify` for client URL matching.
    # @option constraints [Integer] :notBefore If given, must be a timestamp after which the signature was created.
    # @option constraints [Integer] :notAfter If given, must be a timestamp before which the signature was created.
    # @option constraints [Integer] :minSignatures If given, the multi-signature envelope must contain at least this many signatures.
    # @option constraints [Integer] :maxSignatures If given, the multi-signature envelope must contain at most this many signatures.
    #
    # @return [Hash, false, nil] `{type: 'multisig', valid: Boolean, secure: (Boolean, nil), expires: (Integer, nil), verifiedAt: (Integer, nil), signatures: Array<Hash>}`, false or nil:
    #   - `false` upon failed verification,
    #   - `nil` upon time-related constraint failure (so callers can distinguish "expired" from generic failure),
    #   - or a Hash with:
    #     `type` - always the literal `'multisig'`,
    #     `valid` - `true` when every contributing signature verified,
    #     `secure` - `true` only when every contributing signature's identity was DNSSEC-validated; `nil` when there are no results to aggregate,
    #     `expires` - the earliest defined per-signature expiry (ms timestamp), or `nil` if none of the contributing key groups had a TTL,
    #     `verifiedAt` - the latest (max) per-signature verification timestamp (ms) - when the whole envelope finished verifying; `nil` when there are no results to aggregate,
    #     `signatures` - array of per-signature verification results (see `Triauth::Signature#verify` for each entry's shape).
    def verify(message, constraints = {})
      verification_results = []

      constraints = Helpers.object_assign({}, constraints)

      if !Helpers.has_only_known_properties(
        constraints,
        [
          :minSignatures, :maxSignatures, # enforced by this method
          :type, :identifier, :actor, :ver, :via, :notBefore, :notAfter # enforced by Triauth.Signature.verify
        ],
        false
      )
        Helpers.log(@config, :error, 'Unrecognized constraint')
        return false
      end

      # Fail if signature count constraints are provided in a non-numeric form
      if (!constraints[:minSignatures].nil? && (!Helpers.is_number(constraints[:minSignatures]) || (constraints[:minSignatures].is_a?(Float) && constraints[:minSignatures].nan?))) ||
         (!constraints[:maxSignatures].nil? && (!Helpers.is_number(constraints[:maxSignatures]) || (constraints[:maxSignatures].is_a?(Float) && constraints[:maxSignatures].nan?)))
        Helpers.log(@config, :error, 'Invalid minSignatures/maxSignatures constraint')
        return false
      end

      if !constraints[:minSignatures].nil? && @signatures.length < constraints[:minSignatures]
        return false
      end

      constraints.delete(:minSignatures)

      if !constraints[:maxSignatures].nil? && @signatures.length > constraints[:maxSignatures]
        return false
      end

      constraints.delete(:maxSignatures)

      @signatures.each do |signature|
        sig_ver_res = signature.verify(message, constraints)

        if !sig_ver_res || !sig_ver_res[:valid]
          return sig_ver_res.nil? ? nil : false
        end

        verification_results.push(sig_ver_res)
      end

      valid = verification_results.length > 0 && verification_results.all? { |r| r && r[:valid] }
      secure = verification_results.length > 0 ? verification_results.all? { |r| r && r[:secure] } : nil

      # Combine expiries by taking the earliest defined value. An `undefined` expires on any single
      # result means "no expiry constraint from this key" and should not poison the min.
      # When no result carries an expiry, the combined expires is undefined.
      expiries_with_values = verification_results.map { |r| r && r[:expires] }.select { |e| Helpers.is_number(e) }
      expires = expiries_with_values.length > 0 ? expiries_with_values.min : nil

      # Combine per-signature verification timestamps by taking the LATEST: the whole envelope is only
      # fully verified once its slowest signature (e.g., one whose identity DNS blocked) has confirmed.
      # Mirrors the expires filter above so a stray undefined cannot turn Math.max into NaN.
      verified_at_values = verification_results.map { |r| r && r[:verifiedAt] }.select { |v| Helpers.is_number(v) }
      verified_at = verified_at_values.length > 0 ? verified_at_values.max : nil

      return {
        type: 'multisig',
        valid: valid,
        secure: secure,
        expires: expires,
        verifiedAt: verified_at,
        signatures: verification_results
      }
    end
  end
end
