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


require_relative 'base'
require_relative 'registry'
require_relative '../helpers'

module Triauth
  module Verifiers
    # The base abstract verifier for WebAuthn signatures.
    #
    # Performs the WebAuthn-level assertion validation.
    # Subclasses must define concrete import_algorithm, verify_algorithm, and register themselves (e.g., as `webauthn-es256`).
    class WebAuthn < Base
      # The Web Crypto parameters used to import the publishable key and to verify
      # assertion signatures. Concrete subclasses MUST override these to bind a
      # credential algorithm; left nil, the verifier fails closed.

      # @return [Hash, nil] The import algorithm identifier a concrete subclass binds (`{name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'}` or `{name: 'Ed25519'}`); nil here.
      def self.import_algorithm = nil

      # @return [Hash, nil] The verify algorithm identifier a concrete subclass binds (`{name: 'ECDSA', hash: 'SHA-256'}` or `{name: 'Ed25519'}`); nil here.
      def self.verify_algorithm = nil

      # Returns the bytes of a publishable key in the form that the `raw` import of `import_algorithm` accepts.
      # Subclasses whose credential algorithm has more than one key form override it.
      #
      # @param raw_public_key [String] A key as published in the DNS record.
      # @return [String] the key bytes (a binary String).
      #
      # @raise [TypeError] when the key is not in a form that the credential algorithm accepts.
      def self.public_key_bytes(raw_public_key)
        return Helpers.base64url_to_uint8(raw_public_key)
      end

      # @return [OpenSSL::PKey::PKey] The public key the assertion signatures are verified against.
      attr_reader :public_key
      # @return [Hash] Key options as read from the DNS record that contained the public key (see {#initialize}).
      attr_reader :options
      # @return [Hash] Per-verification context (see {#initialize}).
      attr_reader :context
      # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
      attr_reader :config

      # Constructs a new instance of verifier for the given public crypto key and options.
      #
      # @param public_key [OpenSSL::PKey::PKey] A public key in form of an `OpenSSL::PKey` object.
      # @param options [Hash] Key options as read from the DNS record that contained the public_key. Defaults to `{}`.
      #        Supports `uv: 'required'` - assertions are then accepted only with the User Verified (UV) flag set
      #        (i.e., the authenticator checked PIN/biometrics).
      # @param context [Hash] Per-verification context (`idx`, `mode`, `webAuthnOrigin`). `idx` (key's index in its keyGroup) selects
      #        which `unsignedData.sig[idx]` entry to verify against; `webAuthnOrigin`, if set, is enforced against `clientData.origin`.
      #        Stored on `context`. Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      def initialize(public_key, options = {}, context = {}, config = {})
        super()

        @public_key = public_key
        @options = options
        @context = context
        @config = Helpers.merge_config(config)
      end

      # Builds an instance of the Verifier from the raw key information read from the DNS.
      #
      # @param raw_public_key [String] A key as published in the DNS record.
      # @param options [Hash] Key options as read from the DNS record that contained the raw_public_key. Defaults to `{}`.
      # @param context [Hash] Per-verification context (`idx`, `mode`, `webAuthnOrigin`). `idx` (key's index in its keyGroup) selects
      #        which `unsignedData.sig[idx]` entry to verify against; `webAuthnOrigin`, if set, is enforced against `clientData.origin`.
      #        Stored on `context`. Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [WebAuthn, nil] The instance of this verifier, or nil if key is invalid or other problem occurred.
      def self.from_publishable_key(raw_public_key, options = {}, context = {}, config = {})
        config = Helpers.merge_config(config)

        import_algorithm = self.import_algorithm
        if import_algorithm.nil?
          Helpers.log(config, :debug, 'WebAuthn is an algorithm-agnostic base verifier - use a concrete subclass (e.g., WebAuthnEs256)')
          return nil
        end

        begin
          public_key = Base.import_key(public_key_bytes(raw_public_key), import_algorithm)

          return new(public_key, options, context, config)
        rescue StandardError => err
          Helpers.log(config, :debug, err)
          return nil
        end
      end

      # Verifies that a given signature matches the verifier's public key and the given message.
      #
      # @param message [String] The message that was signed; its SHA-256 digest must match `clientData.challenge`.
      # @param signature_base64url [String] Base64Url encoded signature over `(authenticatorData || sha256(clientDataJSON))`.
      # @param signed_data [Hash] Signature envelope's signedMetadata. Unused by this verifier.
      # @param unsigned_data [Hash{Symbol => Object}] Signature envelope's unsignedMetadata. Must contain `sig[idx]` for this key's
      #        index (set on `context[:idx]`; `sig` is an object keyed by the index string, or an array read by position),
      #        carrying the original `clientDataJSON` (string) and `authenticatorData` (base64url, minimum 37 bytes, with the
      #        User Present flag set - silent CTAP-level assertions are rejected).
      #
      # @return [Boolean] true or false basing on the verification result.
      def verify(message, signature_base64url, signed_data, unsigned_data) # rubocop:disable Lint/UnusedMethodArgument -- `signed_data` is the verifier contract, unused here as in triauth-js
        verify_algorithm = self.class.verify_algorithm
        if verify_algorithm.nil?
          Helpers.log(@config, :debug, 'WebAuthn is an algorithm-agnostic base verifier - use a concrete subclass (e.g., WebAuthnEs256)')
          return false
        end

        idx = @context[:idx]
        idx_key = idx.to_s.to_sym # the JS `sig[idx]` looks up the object key `"0"` for the index 0; the JSON key is the Symbol `:"0"` here
        expected_challenge = Helpers.sha256(message)
        expected_origin = @context[:webAuthnOrigin]

        # SECURITY NOTE: `unsigned_data` is NOT covered by the triauth envelope's signature, but:
        #   - clientData.challenge is checked to be the expected_challenge
        #   - (authenticatorData + sha256(clientDataJSON)) is covered by the WebAuthn-signed payload
        if !unsigned_data.is_a?(Hash)
          return false
        end

        sig = unsigned_data[:sig]
        # the JS `sig[idx]` reads an Array by position and an object by its "0" key; both shapes are accepted, as in triauth-js
        entry = nil
        if sig.is_a?(Array)
          entry = sig[idx] if idx.is_a?(Integer) && idx >= 0 # a negative or non-integer index never reads an Array from its end
        elsif sig.is_a?(Hash)
          entry = sig[idx_key]
        end
        if !entry.is_a?(Hash) ||
           !Helpers.is_string(entry[:clientDataJSON]) ||
           !Helpers.is_base64url_string(entry[:authenticatorData])
          return false
        end

        authenticator_data, client_data_json = entry.values_at(:authenticatorData, :clientDataJSON)

        # Verify clientData structure, including that the clientData.challenge is an SHA-256 digest of the message
        client_data = Helpers.safe_parse_json(client_data_json)
        if client_data[:challenge] != expected_challenge ||               # <--- challenge MUST MATCH --- !!!
           client_data_json.scan('"challenge":').length != 1 ||           # Ensure that "challenge" key appears exactly once in the clientDataJSON, as an extra safety precaution
           client_data[:type] != 'webauthn.get' ||                        # type should always be 'webauthn.get'
           (client_data.key?(:crossOrigin) && client_data[:crossOrigin] != false) || # if present, must be exactly false (a cross-origin <iframe> assertion carries true); the member is optional and absent means top-level same-origin (WebKit omits it) - `key?`, not `nil?`: an explicit null is present and rejected, as in triauth-js
           (!expected_origin.nil? && !expected_origin.empty? && client_data[:origin] != expected_origin) # origin, if available from context, must match
          return false
        end

        # Parse the authenticatorData: 32-byte rpIdHash, 1 flags byte, 4-byte signCount (37 bytes minimum)
        authenticator_data_bytes = Helpers.base64url_to_uint8(authenticator_data)
        if authenticator_data_bytes.bytesize < 37
          Helpers.log(@config, :debug, 'WebAuthn assertion rejected - authenticatorData shorter than 37 bytes')
          return false
        end

        # Require the User Present (UP) flag, as the W3C Web Authentication specification mandates for assertions.
        # Browser-mediated assertions always carry UP=1 (the client performs a presence test before
        # returning one); its absence indicates a CTAP-level "silent" assertion (options.up=false),
        # e.g., minted by malware with direct access to a connected authenticator.
        #
        # The rpIdHash (bytes 0-31) is intentionally NOT checked: the public key is pinned in the
        # DNS identity records and a WebAuthn credential only ever signs under its own rpId, so
        # there is no cross-RP credential confusion to prevent; the phishing angle is covered by
        # the clientData.origin check above. The signCount (bytes 33-36) is not checked either:
        # clone detection requires server-side state that this stateless verifier does not have
        # (and modern passkeys report a constant 0).
        if (authenticator_data_bytes.getbyte(32) & 0x01) != 0x01
          Helpers.log(@config, :debug, 'WebAuthn assertion rejected - User Present (UP) flag not set')
          return false
        end

        # When the key record demands user verification (`uv=required`), also require the
        # User Verified (UV) flag - i.e., the authenticator must have checked PIN/biometrics.
        # Key records carrying any other `uv` value never reach this point - they taint their
        # whole keyGroup during Triauth::IdentityKeys#add (fail closed, never silently weaker).
        if @options[:uv] == 'required' && (authenticator_data_bytes.getbyte(32) & 0x04) != 0x04
          Helpers.log(@config, :debug, 'WebAuthn assertion rejected - User Verified (UV) flag required by key options but not set')
          return false
        end

        # Reconstruct the payload that was signed by webauthn
        client_data_hash = OpenSSL::Digest::SHA256.digest(Helpers.string_to_utf8_bytes(client_data_json))

        web_authn_payload = authenticator_data_bytes + client_data_hash

        # Convert the signature being verified back to a binary String for verify_signature
        signature = Helpers.base64url_to_uint8(signature_base64url)

        # Verify the digital signature (may raise an exception if arguments are invalid)
        return Base.verify_signature(verify_algorithm, @public_key, signature, web_authn_payload)
      rescue StandardError => err
        Helpers.log(@config, :debug, err)
        return false
      end
    end

    # A verifier for WebAuthn signatures backed by ECDSA P-256 (ES256) credentials.
    #
    # Shares all WebAuthn assertion validation with the WebAuthn base class; this subclass
    # only binds the ES256 credential algorithm. The publishable key is the 65-byte uncompressed
    # or the 33-byte compressed P-256 point (see `Triauth::Helpers.decode_p256_public_key`).
    class WebAuthnEs256 < WebAuthn
      # @return [Hash] `{name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256'}`
      def self.import_algorithm = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }

      # @return [Hash] `{name: 'ECDSA', hash: 'SHA-256'}`
      def self.verify_algorithm = { name: 'ECDSA', hash: 'SHA-256' }

      # Returns the publishable key as the 65-byte uncompressed P-256 point.
      #
      # @param raw_public_key [String] A key as published in the DNS record.
      # @return [String] the 65-byte uncompressed point (a binary String).
      #
      # @raise [TypeError] when the key is not an uncompressed or a compressed P-256 point.
      def self.public_key_bytes(raw_public_key)
        return Helpers.decode_p256_public_key(Helpers.base64url_to_uint8(raw_public_key))
      end
    end

    # A verifier for WebAuthn signatures backed by Ed25519 (EdDSA over Curve25519) credentials.
    #
    # Shares all WebAuthn assertion validation with the WebAuthn base class; this subclass
    # only binds the Ed25519 credential algorithm. Like the plain Ed25519 verifier, it requires
    # Ed25519 support in the openssl gem (3.x over OpenSSL 1.1.1 or later) - on runtimes without it,
    # `from_publishable_key` returns nil and the keyGroup fails verification (fail closed).
    class WebAuthnEd25519 < WebAuthn
      # @return [Hash] `{name: 'Ed25519'}`
      def self.import_algorithm = { name: 'Ed25519' }

      # @return [Hash] `{name: 'Ed25519'}`
      def self.verify_algorithm = { name: 'Ed25519' }
    end

    Triauth::Verifiers.register('webauthn-es256', WebAuthnEs256)
    Triauth::Verifiers.register('webauthn-ed25519', WebAuthnEd25519)
  end
end
