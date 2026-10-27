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
require 'securerandom'
require_relative 'helpers'

module Triauth
  # Seals and opens the requests that follow a sign-in (ping, sign, stamp and attest), so that the redirect URL and
  # the browser history show no identifier and no message.
  #
  # The client application seals the challenge with AES-128-GCM, under a request key that HKDF-SHA256 (RFC 5869)
  # derives from the session key of the sign-in. The request also contains `skid`, a short hash of the session key,
  # so that the authenticator can find the key. Only the client application and the authenticator know the session
  # key, so a request that opens also proves where it comes from.
  #
  # A sealed request is `<iv>.<ciphertext>`, both base64url. The plaintext is the JSON of the challenge.
  class RequestCipher
    # The HKDF `info` of the request key
    REQUEST_KEY_INFO = Helpers.string_to_utf8_bytes('triauth/request/v1')
    private_constant :REQUEST_KEY_INFO

    # Computes the session key ID, which the request contains readable so that the authenticator can find the key.
    # It is the first 16 bytes of the SHA-256 of the 32 bytes of the session key.
    #
    # @param session_key [String] the session key, 43 base64url characters, without the domain of a delegated key.
    #
    # @return [String] the session key ID, 22 base64url characters.
    def self.skid(session_key)
      digest = OpenSSL::Digest::SHA256.digest(Helpers.base64url_to_uint8(session_key))
      return Helpers.array_buffer_to_base64url(digest[0, 16])
    end

    # Seals a challenge under the session key. This is the client application's side.
    #
    # @param session_key [String] the session key, 43 base64url characters, without the domain of a delegated key.
    # @param challenge [String] the challenge, base64url.
    #
    # @return [String] the sealed request, `<iv>.<ciphertext>`.
    def self.seal(session_key, challenge)
      # The IV comes from `SecureRandom` and never from `randomSource`. A repeated IV under one key breaks AES-GCM.
      iv = SecureRandom.random_bytes(12)
      key = request_key(session_key)
      pt = Helpers.base64url_to_uint8(challenge)
      cipher = OpenSSL::Cipher.new('aes-128-gcm').encrypt
      cipher.key = key
      cipher.iv = iv
      # Web Crypto appends the 16-byte tag to the ciphertext. `Cipher#update` is never called with an empty string (some
      # OpenSSL bindings refuse it), so an empty challenge seals to the tag alone, as Web Crypto gives.
      ct = (pt.empty? ? ''.b : cipher.update(pt)) + cipher.final + cipher.auth_tag

      return "#{Helpers.array_buffer_to_base64url(iv)}.#{Helpers.array_buffer_to_base64url(ct)}"
    end

    # Opens a sealed request with the session key. This is the authenticator's side.
    #
    # @param session_key [String] the session key, 43 base64url characters, without the domain of a delegated key.
    # @param sealed_request [String] the sealed request, `<iv>.<ciphertext>`.
    #
    # @return [String] the challenge, base64url.
    #
    # @raise [TypeError] when the sealed request is malformed.
    # @raise [OpenSSL::Cipher::CipherError] when the request does not open under this session key.
    def self.open(session_key, sealed_request)
      s = sealed_request.to_s
      parts = s.empty? ? [''] : s.split('.', -1) # `String(x).split('.')`: JS splits `''` into `['']`, Ruby into `[]`
      iv, ct, rest = parts

      if !rest.nil? || iv.nil? || iv.length != 16 || ct.nil? || ct.empty?
        raise TypeError, 'Malformed sealed request'
      end

      iv_bytes = Helpers.base64url_to_uint8(iv)
      key = request_key(session_key)
      ct_bytes = Helpers.base64url_to_uint8(ct)
      # Web Crypto's decrypt throws for a ciphertext shorter than its 16-byte tag, while OpenSSL would check a truncated
      # tag: the length is refused here.
      if ct_bytes.bytesize < 16
        raise TypeError, 'Malformed ciphertext'
      end

      cipher = OpenSSL::Cipher.new('aes-128-gcm').decrypt
      cipher.key = key
      cipher.iv = iv_bytes
      cipher.auth_tag = ct_bytes[-16..] # the tag follows the ciphertext, as Web Crypto lays it out
      # `Cipher#update` is never called with an empty string (see `seal`); a wrong tag raises `OpenSSL::Cipher::CipherError`
      pt = (ct_bytes.bytesize == 16 ? ''.b : cipher.update(ct_bytes[0...-16])) + cipher.final

      return Helpers.array_buffer_to_base64url(pt)
    end

    # Derives the AES-128-GCM request key from the session key with HKDF-SHA256 (RFC 5869). The empty salt acts as 32
    # zero bytes, and the info label keeps this key apart from any other key of the session.
    #
    # @param session_key [String] the session key, 43 base64url characters.
    #
    # @return [String] the request key, 16 raw bytes (a binary String).
    def self.request_key(session_key)
      # the `usage` parameter (`encrypt` or `decrypt`, a Web Crypto key-usage flag) has no counterpart: the raw bytes are the key
      ikm = Helpers.base64url_to_uint8(session_key)
      return OpenSSL::KDF.hkdf(ikm, salt: ''.b, info: REQUEST_KEY_INFO, length: 16, hash: 'SHA256')
    end
    private_class_method :request_key
  end
end
