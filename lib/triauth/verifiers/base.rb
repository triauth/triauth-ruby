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


require 'openssl'

module Triauth
  module Verifiers
    # The base abstract class from which all Verifiers inherit common functions.
    class Base
      # Constructs a verifier for a public key as it is published in an identity record.
      #
      # This is the abstract contract that concrete verifiers (e.g., Ecdsa, Ed25519, WebAuthn) implement.
      #
      # @param raw_public_key [String] The publishable key material, as read from the identity record.
      # @param options [Hash] Key options as read from the DNS record that carried the key (e.g., `use`, `uv`). Defaults to `{}`.
      # @param context [Hash] Per-verification context threaded through from `Triauth::IdentityKeys#verify`
      #                       (e.g., `idx`, `mode`, `webAuthnOrigin`). Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Base, nil] A verifier instance, or nil when the key
      #         material cannot be imported. A key whose verifier cannot be constructed is skipped, never trusted.
      def self.from_publishable_key(raw_public_key, options = {}, context = {}, config = {}) # rubocop:disable Lint/UnusedMethodArgument -- the abstract contract keeps its parameters
        raise 'Triauth.Verifiers.Base.fromPublishableKey is abstract and must be implemented by a subclass'
      end

      # Verifies that a given signature matches the verifier's public key and the given message.
      #
      # This is the abstract contract that concrete verifiers (e.g., Ecdsa, Ed25519, WebAuthn) implement.
      #
      # @param message [String] The message to verify against.
      # @param signature_base64url [String] Base64Url encoded signature.
      # @param signed_data [Hash] Signature envelope's signedMetadata.
      # @param unsigned_data [Hash] Signature envelope's unsignedMetadata.
      #
      # @return [Boolean] true or false basing on the verification result.
      def verify(message, signature_base64url, signed_data, unsigned_data) # rubocop:disable Lint/UnusedMethodArgument -- the abstract contract keeps its parameters
        raise 'Triauth.Verifiers.Base#verify is abstract and must be implemented by a subclass'
      end

      # Crypto encodings with no triauth-js counterpart (the profile's idiom table): byte conversions only, all math is OpenSSL's.

      # The `SubjectPublicKeyInfo` prefix of an Ed25519 public key (`SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }` ahead
      # of the 32 raw key bytes): `OpenSSL::PKey` reads a raw key through this wrapper only.
      ED25519_SPKI_PREFIX = ['302a300506032b6570032100'].pack('H*').freeze
      private_constant :ED25519_SPKI_PREFIX

      # The port of `crypto.subtle.importKey('raw', raw_bytes, algorithm, true, ['verify'])`: reads a raw public key through
      # its SPKI DER wrapper, so that OpenSSL validates the key material (a P-256 point that is not on the curve is rejected).
      #
      # @param raw_bytes [String] The raw public key (a binary String): the 65-byte uncompressed point `04 || X || Y` for
      #                           ECDSA P-256 (the verifiers decode a compressed point to this form first, with
      #                           `Helpers.decode_p256_public_key`; the import itself still refuses every other form before
      #                           OpenSSL sees it), the 32 raw bytes for Ed25519.
      # @param algorithm [Hash] The WebCrypto import algorithm identifier, kept as data:
      #                         `{name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'}` or `{name: 'Ed25519'}`.
      #
      # @return [OpenSSL::PKey::PKey] the public key (an `OpenSSL::PKey::EC` for ECDSA).
      #
      # @raise [ArgumentError] when the bytes do not have the length (and prefix) of the algorithm's raw form, or the
      #                        algorithm identifier is not one of the two above.
      # @raise [OpenSSL::PKey::PKeyError] when OpenSSL rejects the key material (e.g., a point that is not on the curve).
      def self.import_key(raw_bytes, algorithm)
        case algorithm[:name]
        when 'ECDSA'
          raise ArgumentError, "Unsupported ECDSA curve: #{algorithm[:namedCurve]}" unless algorithm[:namedCurve] == 'P-256'
          raise ArgumentError, 'ECDSA raw public key must be the 65-byte uncompressed point' unless raw_bytes.bytesize == 65 && raw_bytes.getbyte(0) == 0x04

          # SPKI: SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING point }
          algorithm_identifier = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId('id-ecPublicKey'), OpenSSL::ASN1::ObjectId('prime256v1')])
          der = OpenSSL::ASN1::Sequence([algorithm_identifier, OpenSSL::ASN1::BitString(raw_bytes)]).to_der
          return OpenSSL::PKey::EC.new(der)
        when 'Ed25519'
          raise ArgumentError, 'Ed25519 raw public key must be 32 bytes' unless raw_bytes.bytesize == 32

          return OpenSSL::PKey.read(ED25519_SPKI_PREFIX + raw_bytes)
        else
          raise ArgumentError, "Unsupported algorithm: #{algorithm[:name]}"
        end
      end

      # The port of `crypto.subtle.verify(algorithm, public_key, signature_bytes, data_bytes)`: verifies the raw signature of
      # the wire (`r || s` for ECDSA, the 64 raw bytes for Ed25519) over the data bytes. The length is checked before any
      # conversion, so a DER-encoded ECDSA signature is refused exactly as WebCrypto refuses it (no widened accept-set).
      #
      # @param algorithm [Hash] The WebCrypto verify algorithm identifier, kept as data:
      #                         `{name: 'ECDSA', hash: 'SHA-256'}` or `{name: 'Ed25519'}`.
      # @param public_key [OpenSSL::PKey::PKey] The public key, as returned by {Triauth::Verifiers::Base.import_key}.
      # @param signature_bytes [String] The raw signature (a binary String): exactly 64 bytes for both algorithms.
      # @param data_bytes [String] The signed data (a binary String).
      #
      # @return [Boolean] true when the signature verifies; false for a signature of another length, a signature that does
      #                   not verify, or an operation OpenSSL refuses (`OpenSSL::PKey::PKeyError`).
      #
      # @raise [ArgumentError] when the algorithm identifier is not one of the two above.
      def self.verify_signature(algorithm, public_key, signature_bytes, data_bytes)
        case algorithm[:name]
        when 'ECDSA'
          raise ArgumentError, "Unsupported ECDSA hash: #{algorithm[:hash]}" unless algorithm[:hash] == 'SHA-256'
          return false unless signature_bytes.bytesize == 64

          return public_key.verify('SHA256', raw_to_der(signature_bytes), data_bytes)
        when 'Ed25519'
          return false unless signature_bytes.bytesize == 64

          return public_key.verify(nil, signature_bytes, data_bytes)
        else
          raise ArgumentError, "Unsupported algorithm: #{algorithm[:name]}"
        end
      rescue OpenSSL::PKey::PKeyError
        return false
      end

      # Converts a raw ECDSA signature `r || s` (two 32-byte big-endian unsigned integers) into the DER
      # `SEQUENCE { INTEGER r, INTEGER s }` that OpenSSL verifies. `OpenSSL::ASN1::Integer` writes the minimal positive
      # encodings (a leading zero byte ahead of a high bit, leading zero bytes dropped).
      #
      # @param signature_bytes [String] The 64-byte raw signature (a binary String).
      #
      # @return [String] the DER-encoded signature (a binary String).
      #
      # @raise [ArgumentError] when the signature is not 64 bytes.
      def self.raw_to_der(signature_bytes)
        raise ArgumentError, 'ECDSA raw signature must be 64 bytes' unless signature_bytes.bytesize == 64

        r = OpenSSL::BN.new(signature_bytes.byteslice(0, 32), 2)
        s = OpenSSL::BN.new(signature_bytes.byteslice(32, 32), 2)
        return OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(r), OpenSSL::ASN1::Integer(s)]).to_der
      end
    end
  end
end
