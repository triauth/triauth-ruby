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
require_relative 'helpers'

module Triauth
  # Seals and opens the responses of the challenge-response flows, so that a response travels only as ciphertext.
  #
  # The construction is HPKE, Hybrid Public Key Encryption (RFC 9180, https://www.rfc-editor.org/rfc/rfc9180). HPKE
  # encrypts a message to a public key in three steps. The sender makes a one-time key pair and runs ECDH with the
  # recipient's public key to get a shared secret. HKDF derives an AES key and a nonce from that secret. AES-GCM encrypts
  # the message and adds a tag that detects any change. The sender's one-time public key (`enc`) goes with the
  # ciphertext. With it, the recipient runs ECDH with its private key and derives the same AES key.
  #
  # This class uses the DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM suite in base mode, single shot. Base
  # mode has no pre-shared key and does not authenticate the sender. The signatures inside the response do that. Single
  # shot means that each key schedule encrypts one message.
  #
  # The client application mints a fresh key pair for every challenge. The challenge contains the public key as `ek`,
  # and the private key stays with the stored challenge. The Triauth Authenticator seals the response to `ek`, so only
  # the holder of the stored challenge can open it.
  #
  # A sealed response is `<enc>.<ciphertext>`, both base64url.
  #
  # Sealing and opening a response give both sides the same session key. HPKE secret export (RFC 9180, section 5.3)
  # derives it from the encryption context of the response, so the key never travels. The session key does not open
  # any response, because the export is separate from the AES key and the nonce.
  class ResponseCipher
    # `P256` (the Web Crypto ECDH descriptor of the curve) is the curve group here; every byte value below is a binary String
    GROUP = OpenSSL::PKey::EC::Group.new('prime256v1')
    EMPTY = ''.b

    # The version label at the start of every labeled HKDF input (RFC 9180, section 4)
    HPKE_V1 = Helpers.string_to_utf8_bytes('HPKE-v1')

    # The suite identifiers of the labeled HKDF steps, with the IDs from RFC 9180, section 7. KEM_ID is "KEM" and the KEM
    # ID 0x0010 for DHKEM(P-256, HKDF-SHA256), as in RFC 9180, section 4.1. SUITE_ID is "HPKE", the same KEM ID, the KDF ID
    # 0x0001 for HKDF-SHA256 and the AEAD ID 0x0001 for AES-128-GCM, as in RFC 9180, section 5.1.
    KEM_ID = [0x4b, 0x45, 0x4d, 0x00, 0x10].pack('C*')
    SUITE_ID = [0x48, 0x50, 0x4b, 0x45, 0x00, 0x10, 0x00, 0x01, 0x00, 0x01].pack('C*')

    # The `info` of the key schedule (RFC 9180, section 5.1). It binds every sealed response to this protocol and version,
    # so a response sealed for another application or version does not open.
    INFO = Helpers.string_to_utf8_bytes('triauth/response/v1')

    # The `exporter_context` of the session key (RFC 9180, section 5.3)
    SESSION_KEY = Helpers.string_to_utf8_bytes('triauth/session-key')
    private_constant :GROUP, :EMPTY, :HPKE_V1, :KEM_ID, :SUITE_ID, :INFO, :SESSION_KEY

    # Mints a fresh key pair for one challenge.
    #
    # @return [Hash] `{encryptionKey: String, decryptionKey: String}`: `encryptionKey` is the public key for the
    #         challenge's `ek`, an uncompressed P-256 point in 87 base64url characters. `decryptionKey` is the private
    #         scalar in 43 base64url characters, which stays with the stored challenge.
    def self.generate_key_pair
      key_pair = OpenSSL::PKey::EC.generate('prime256v1')

      # `exportKey('raw')` is the uncompressed point; `exportKey('jwk').d` is the 32-byte scalar (`BN#to_s(2)` drops
      # leading zeros, so it is left-padded back to 32 bytes)
      return {
        encryptionKey: Helpers.array_buffer_to_base64url(key_pair.public_key.to_octet_string(:uncompressed)),
        decryptionKey: Helpers.array_buffer_to_base64url(key_pair.private_key.to_s(2).rjust(32, "\x00".b))
      }
    end

    # Seals a response envelope to the challenge's encryption key. This is the authenticator's side. Every call makes a
    # new one-time key pair, so the same envelope seals to different bytes and a different session key each time.
    #
    # @param encryption_key [String] the challenge's `ek`.
    # @param response [String] the response envelope (`|...|`).
    #
    # @return [Hash] `{sealedResponse: String, sessionKey: String}`: the sealed response, `<enc>.<ciphertext>`, and
    #         the session key of this response in 43 base64url characters.
    #
    # @raise [TypeError, OpenSSL::PKey::EC::Point::Error] when the encryption key is not a P-256 point.
    def self.seal(encryption_key, response)
      enc, ct, exporter_secret = seal_base(Helpers.base64url_to_uint8(encryption_key), INFO, EMPTY, Helpers.string_to_utf8_bytes(response)).values_at(:enc, :ct, :exporterSecret)

      return {
        sealedResponse: "#{Helpers.array_buffer_to_base64url(enc)}.#{Helpers.array_buffer_to_base64url(ct)}",
        sessionKey: Helpers.array_buffer_to_base64url(export(exporter_secret, SESSION_KEY, 32))
      }
    end

    # Opens a sealed response with the key pair of its challenge. This is the client application's side.
    #
    # @param encryption_key [String] the challenge's `ek`.
    # @param decryption_key [String] the private scalar kept with the stored challenge.
    # @param sealed_response [String] the sealed response, `<enc>.<ciphertext>`.
    #
    # @return [Hash] `{response: String, sessionKey: String}`: the response envelope, and the session key of this
    #         response in 43 base64url characters, the same that `seal` gave.
    #
    # @raise [TypeError] when the sealed response is malformed.
    # @raise [OpenSSL::Cipher::CipherError] when the response was not sealed to this key pair.
    def self.open(encryption_key, decryption_key, sealed_response)
      s = sealed_response.to_s
      parts = s.empty? ? [''] : s.split('.', -1) # `String(x).split('.')`: JS splits `''` into `['']`, Ruby into `[]`
      enc, ct, rest = parts

      if !rest.nil? || enc.nil? || enc.empty? || ct.nil? || ct.empty?
        raise TypeError, 'Malformed sealed response'
      end

      pk_rm = Helpers.base64url_to_uint8(encryption_key)
      # `importKey('jwk', {kty, crv, d, x, y})`: OpenSSL has no JWK import, so the key is built from the same fields
      # through the SEC1 `ECPrivateKey` DER (as `test/stubs/signer.rb` does); the base64url hops of `x` and `y` have no counterpart
      sk_r = import_jwk(Helpers.base64url_to_uint8(decryption_key), pk_rm[1, 32], pk_rm[33, 32])

      pt, exporter_secret = open_base(Helpers.base64url_to_uint8(enc), sk_r, pk_rm, INFO, EMPTY, Helpers.base64url_to_uint8(ct)).values_at(:pt, :exporterSecret)

      return {
        response: Helpers.utf8_bytes_to_string(pt),
        sessionKey: Helpers.array_buffer_to_base64url(export(exporter_secret, SESSION_KEY, 32))
      }
    end

    # HPKE single-shot seal in base mode (RFC 9180, section 6.1). Encap makes the one-time key pair and the shared
    # secret (RFC 9180, section 4.1). The key schedule derives the AES key and nonce (RFC 9180, section 5.1). AES-GCM
    # then encrypts the plaintext.
    #
    # @param pk_rm [String] the recipient's public key, an uncompressed P-256 point (a binary String).
    # @param info [String] the application context (a binary String).
    # @param aad [String] the associated data, authenticated but not encrypted (a binary String).
    # @param pt [String] the plaintext (a binary String).
    # @param ephemeral [OpenSSL::PKey::EC, nil] a fixed sender key pair (the one OpenSSL key holds both halves), only
    #   for known-answer tests such as the RFC 9180 test vector A.3.1. Reusing it for the same recipient repeats the AES
    #   key and nonce, which breaks AES-GCM. Defaults to nil.
    #
    # @return [Hash] `{enc: String, ct: String, exporterSecret: String}` (binary Strings): the encapsulated key (the
    #         sender's one-time public key), the ciphertext with its 16-byte tag, and the exporter secret for `export`.
    #
    # @raise [TypeError, OpenSSL::PKey::EC::Point::Error] when the recipient's public key is not an uncompressed point on the P-256 curve.
    def self.seal_base(pk_rm, info, aad, pt, ephemeral = nil)
      ephemeral = OpenSSL::PKey::EC.generate('prime256v1') if ephemeral.nil?

      # `ephemeral.publicKey` and `ephemeral.privateKey` are the two halves of the one OpenSSL key
      enc = ephemeral.public_key.to_octet_string(:uncompressed)
      key, nonce, exporter_secret = key_schedule(ecdh(ephemeral, pk_rm), enc, pk_rm, info).values_at(:key, :nonce, :exporterSecret)
      cipher = OpenSSL::Cipher.new('aes-128-gcm').encrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_data = aad
      # Web Crypto appends the 16-byte tag to the ciphertext. `Cipher#update` is never called with an empty string (some
      # OpenSSL bindings refuse it), so an empty plaintext encrypts to the tag alone, as Web Crypto gives.
      ct = (pt.empty? ? ''.b : cipher.update(pt)) + cipher.final + cipher.auth_tag

      return { enc: enc, ct: ct, exporterSecret: exporter_secret }
    end

    # HPKE single-shot open in base mode (RFC 9180, section 6.1). Decap recovers the shared secret from `enc` and the
    # recipient's private key (RFC 9180, section 4.1). The key schedule derives the same AES key and nonce (RFC 9180,
    # section 5.1). AES-GCM then decrypts the ciphertext and checks its tag.
    #
    # @param enc [String] the encapsulated key, the sender's one-time public key (a binary String).
    # @param sk_r [OpenSSL::PKey::EC] the recipient's private key.
    # @param pk_rm [String] the recipient's public key, an uncompressed P-256 point (a binary String).
    # @param info [String] the application context (a binary String).
    # @param aad [String] the associated data (a binary String).
    # @param ct [String] the ciphertext with its tag (a binary String).
    #
    # @return [Hash] `{pt: String, exporterSecret: String}` (binary Strings): the plaintext, and the exporter secret for
    #         `export`.
    #
    # @raise [OpenSSL::Cipher::CipherError] when the ciphertext does not authenticate under this key pair.
    # @raise [TypeError, OpenSSL::PKey::EC::Point::Error] when `enc` is not an uncompressed point on the P-256 curve, or the ciphertext is shorter than its tag.
    def self.open_base(enc, sk_r, pk_rm, info, aad, ct)
      key, nonce, exporter_secret = key_schedule(ecdh(sk_r, enc), enc, pk_rm, info).values_at(:key, :nonce, :exporterSecret)
      # Web Crypto's decrypt throws for a ciphertext shorter than its 16-byte tag, while OpenSSL would check a truncated
      # tag: the length is refused here.
      if ct.bytesize < 16
        raise TypeError, 'Malformed ciphertext'
      end

      cipher = OpenSSL::Cipher.new('aes-128-gcm').decrypt
      cipher.key = key
      cipher.iv = nonce
      cipher.auth_tag = ct[-16..] # the tag follows the ciphertext, as Web Crypto lays it out; set before the associated data
      cipher.auth_data = aad
      # `Cipher#update` is never called with an empty string (see `seal_base`); a wrong tag raises `OpenSSL::Cipher::CipherError`
      pt = (ct.bytesize == 16 ? ''.b : cipher.update(ct[0...-16])) + cipher.final

      return { pt: pt, exporterSecret: exporter_secret }
    end

    # HPKE secret export (RFC 9180, section 5.3). It derives a secret from the encryption context of one message. The
    # sender and the recipient get the same value without sending it. Each `exporter_context` gives a different secret,
    # and an exported secret does not reveal the AES key or the nonce.
    #
    # @param exporter_secret [String] the exporter secret of the context, from `seal_base` or `open_base` (a binary String).
    # @param exporter_context [String] the label of the exported secret (a binary String).
    # @param length [Integer] the length in bytes, from 1 to 32.
    #
    # @return [String] the exported secret (a binary String).
    #
    # @raise [RangeError] when the length is not from 1 to 32.
    def self.export(exporter_secret, exporter_context, length)
      # `Number.isInteger(length)` on an Integer argument: a Float such as `32.0` is an integer in JS and is refused here (no caller passes one)
      if !length.is_a?(Integer) || length < 1 || length > 32
        raise RangeError, 'Invalid export length'
      end

      # LabeledExpand(exporter_secret, "sec", exporter_context, L). Up to 32 bytes, HKDF-Expand is one block,
      # HMAC(exporter_secret, info || 0x01) (RFC 5869, section 2.3). Web Crypto's HKDF always runs Extract first.
      labeled_info = concat([0x00, length].pack('C*'), HPKE_V1, SUITE_ID, Helpers.string_to_utf8_bytes('sec'), exporter_context, "\x01".b)
      return Helpers.hmac_sha256(exporter_secret, labeled_info)[0, length]
    end

    # P-256 Diffie-Hellman, the DH() function of the DHKEM (RFC 9180, section 4.1). Its result is the x-coordinate of
    # the shared point, 32 bytes. The public key must be an uncompressed point (RFC 9180, section 7.1.1). The point
    # import rejects a point that is not on the curve, as RFC 9180, section 7.1.4 requires.
    #
    # @param private_key [OpenSSL::PKey::EC] this side's private key, the sender's one-time key or the recipient's key.
    # @param public_key_bytes [String] the other side's public key, an uncompressed P-256 point of 65 bytes (a binary String).
    #
    # @return [String] the 32-byte Diffie-Hellman shared secret (a binary String).
    #
    # @raise [TypeError, OpenSSL::PKey::EC::Point::Error] when the public key is not an uncompressed point on the P-256 curve.
    def self.ecdh(private_key, public_key_bytes)
      # explicit before the import: `Point.new` would decode a compressed point as well (probe 11)
      if public_key_bytes.bytesize != 65 || public_key_bytes.getbyte(0) != 0x04
        raise TypeError, 'Invalid public key'
      end

      # `importKey('raw', ...)`: `Point.new` refuses a point that is not on the curve with `OpenSSL::PKey::EC::Point::Error`
      public_key = OpenSSL::PKey::EC::Point.new(GROUP, OpenSSL::BN.new(public_key_bytes, 2))
      return private_key.dh_compute_key(public_key)
    end

    # Derives the AES key, the nonce and the exporter secret for one message. ExtractAndExpand derives the KEM shared
    # secret from the DH result and both public keys (RFC 9180, section 4.1). KeySchedule then derives the key, the base
    # nonce and the exporter secret for base mode, with an empty pre-shared key (RFC 9180, section 5.1). One message per
    # context means sequence number 0, so the nonce is the base nonce itself (RFC 9180, section 5.2).
    #
    # @param dh [String] the 32-byte Diffie-Hellman shared secret (a binary String).
    # @param enc [String] the sender's one-time public key (a binary String).
    # @param pk_rm [String] the recipient's public key, an uncompressed P-256 point (a binary String).
    # @param info [String] the application context (a binary String).
    #
    # @return [Hash] `{key: String, nonce: String, exporterSecret: String}` (binary Strings): the AES-128-GCM key, the
    #         12-byte nonce and the 32-byte exporter secret.
    def self.key_schedule(dh, enc, pk_rm, info)
      shared_secret = hkdf(KEM_ID, EMPTY, 'eae_prk', dh, 'shared_secret', concat(enc, pk_rm), 32)
      # mode_base (0x00), then the hashes of the empty PSK ID and of info
      context = concat("\x00".b, extract('psk_id_hash', EMPTY), extract('info_hash', info))
      key = hkdf(SUITE_ID, shared_secret, 'secret', EMPTY, 'key', context, 16)

      # `importKey('raw', key, 'AES-GCM')` has no counterpart: the 16 raw bytes are the key
      return {
        key: key,
        nonce: hkdf(SUITE_ID, shared_secret, 'secret', EMPTY, 'base_nonce', context, 12),
        exporterSecret: hkdf(SUITE_ID, shared_secret, 'secret', EMPTY, 'exp', context, 32)
      }
    end

    # LabeledExtract followed by LabeledExpand (RFC 9180, section 4). OpenSSL's HKDF runs Extract and then Expand
    # (RFC 5869), so one call does both. The labeled inputs start with "HPKE-v1", the suite ID and the step's label.
    # This keeps every derived value apart from the others.
    #
    # @param suite_id [String] KEM_ID for the DHKEM step, SUITE_ID for the key schedule (a binary String).
    # @param salt [String] the Extract salt (a binary String). An empty salt acts as 32 zero bytes (RFC 5869, section 2.2).
    # @param extract_label [String] the LabeledExtract label, such as `eae_prk`.
    # @param ikm [String] the input keying material (a binary String).
    # @param expand_label [String] the LabeledExpand label, such as `shared_secret`.
    # @param info [String] the LabeledExpand context (a binary String).
    # @param length [Integer] the output length in bytes, below 256.
    #
    # @return [String] the derived bytes (a binary String).
    def self.hkdf(suite_id, salt, extract_label, ikm, expand_label, info, length)
      labeled_ikm = concat(HPKE_V1, suite_id, Helpers.string_to_utf8_bytes(extract_label), ikm)
      labeled_info = concat([0x00, length].pack('C*'), HPKE_V1, suite_id, Helpers.string_to_utf8_bytes(expand_label), info)
      # `importKey('raw', labeledIkm, 'HKDF')` and `deriveBits` are the one call below; an empty salt acts as 32 zero bytes here too (probe 11)
      return OpenSSL::KDF.hkdf(labeled_ikm, salt: salt, info: labeled_info, length: length, hash: 'SHA256')
    end

    # LabeledExtract with an empty salt (RFC 9180, section 4), for `psk_id_hash` and `info_hash`. RFC 5869 sets a
    # missing salt to 32 zero bytes for SHA-256. HMAC under 32 zero bytes gives the same result as HMAC under an empty
    # key, which Web Crypto refuses.
    #
    # @param label [String] the label, `psk_id_hash` or `info_hash`.
    # @param ikm [String] the input keying material (a binary String).
    #
    # @return [String] the 32-byte pseudorandom key (a binary String).
    def self.extract(label, ikm)
      return Helpers.hmac_sha256("\x00".b * 32, concat(HPKE_V1, SUITE_ID, Helpers.string_to_utf8_bytes(label), ikm))
    end

    # Joins byte strings in order, the concat() of RFC 9180.
    #
    # @param parts [Array<String>] the byte strings (binary Strings).
    #
    # @return [String] the joined bytes (a binary String).
    def self.concat(*parts)
      # every part is a binary String, so `join` is the byte concatenation (no `Uint8Array` to size and fill)
      return parts.join
    end

    # Crypto encoding with no triauth-js counterpart (the profile's idiom table): the port of
    # `crypto.subtle.importKey('jwk', {kty: 'EC', crv: 'P-256', d, x, y}, P256, false, ['deriveBits'])`. OpenSSL has no
    # JWK import, so the private key is read through the SEC1 `ECPrivateKey` DER of the scalar and the point
    # `04 || x || y` (the construction of `test/stubs/signer.rb`); OpenSSL refuses a malformed point encoding.
    #
    # @param d [String] the private scalar, 32 bytes (a binary String).
    # @param x [String] the x-coordinate of the public point, 32 bytes (a binary String).
    # @param y [String] the y-coordinate of the public point, 32 bytes (a binary String).
    #
    # @return [OpenSSL::PKey::EC] the private key (it holds both halves).
    #
    # @raise [StandardError] when the DER does not read as a P-256 private key (`OpenSSL::PKey::ECError`, or the
    #                        `ArgumentError` of the constructor's curve-name fallback for a point of another length).
    def self.import_jwk(d, x, y)
      ec_private_key = OpenSSL::ASN1::Sequence(
        [
          OpenSSL::ASN1::Integer(1),
          OpenSSL::ASN1::OctetString(d),
          OpenSSL::ASN1::ObjectId('prime256v1', 0, :EXPLICIT),
          OpenSSL::ASN1::BitString("\x04".b + x + y, 1, :EXPLICIT)
        ]
      )
      return OpenSSL::PKey::EC.new(ec_private_key.to_der)
    end
    private_class_method :ecdh, :key_schedule, :hkdf, :extract, :concat, :import_jwk
  end
end
