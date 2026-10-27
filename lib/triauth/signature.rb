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


require 'json'
require_relative 'error'
require_relative 'helpers'
require_relative 'validator'
require_relative 'protocol'
require_relative 'identity'

module Triauth
  # A single triauth signature envelope, that carries structured information about the signer, and other data,
  # along with the plain cryptographic signatures.
  #
  # Wire format: `|type;identifier;actor;via;v1;ts;signedMetadata;unsignedMetadata;cryptoSignature(s)|`
  class Signature
    # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
    attr_reader :config
    # @return [String] The wrapped signature envelope this instance was parsed from.
    attr_reader :raw_data
    # @return [String] The flow the signature was made for - one of `attest`, `auth`, `ping`, `sign`, `stamp`.
    attr_reader :type
    # @return [String] The identifier of the account the signature speaks for.
    attr_reader :identifier
    # @return [String] The delegated actor that produced the signature, or `''` when the account signed for itself.
    attr_reader :actor
    # @return [String] The canonical URL of the client application the signature was issued to.
    attr_reader :via
    # The protocol version token as published (e.g., `v1`); re-parsed into its integer below.
    # @return [Integer]
    attr_reader :ver
    # The signing timestamp as published; re-parsed into an integer (ms) below.
    # @return [Integer]
    attr_reader :ts
    # @return [String] The signed metadata slot, base64url as carried on the wire, or `''` when the envelope carries none.
    attr_reader :encoded_signed_metadata
    # @return [String] The unsigned metadata slot, base64url as carried on the wire, or `''` when the envelope carries none.
    attr_reader :encoded_unsigned_metadata
    # @return [Array<String>] The envelope's crypto signatures (base64url), one per key in the signing key group.
    attr_accessor :crypto_signatures
    # @return [Hash{Symbol => Object}] The decoded metadata covered by the crypto signatures; `{}` when the envelope carries none.
    attr_reader :signed_metadata
    # @return [Hash{Symbol => Object}] The decoded metadata NOT covered by the crypto signatures; `{}` when the envelope carries none.
    attr_reader :unsigned_metadata

    # Generates a signature envelope by signing the payload with the provided crypto_signer.
    #
    # @param crypto_signer [Proc] a callable that receives the payload string (and a mutable unsignedMetadata reference) and returns one or more base64url crypto signatures.
    # @param type [String] the flow type of the signature ('attest'|'auth'|'ping'|'sign'|'stamp').
    # @param identifier [String] the identifier (the subject) the signature is made for.
    # @param actor [String] the identifier of the delegate whose keys sign on behalf of the `identifier`, or `''` for a non-delegated signature.
    # @param via [String] the base URL of the client application the signature is produced for.
    # @param message [String] the message to sign.
    # @param signed_metadata [Hash] additional data embedded under the crypto signatures. Defaults to `{}`.
    # @param unsigned_metadata [Hash] additional data embedded outside the signed payload (the crypto_signer may populate it). Defaults to `{}`.
    # @param config [Hash] optional overrides for the global Triauth.config settings. Defaults to `{}`.
    #
    # @return [String, false] the signature envelope, or false when the passed values fail validation.
    def self.generate(crypto_signer, type, identifier, actor, via, message, signed_metadata = {}, unsigned_metadata = {}, config = {})
      config = Helpers.merge_config(config)

      Helpers.log(config, :debug, 'Generating signature', { type: type, identifier: identifier, actor: actor, via: via, message: message, signedMetadata: signed_metadata, unsignedMetadata: unsigned_metadata })

      if !(!type.nil? && type != '' && Protocol::FLOWS.include?(type)) ||
         !Validator.validate_identifier(identifier)[:valid] ||
         !(actor == '' || Validator.validate_identifier(actor)[:valid]) ||
         !(Helpers.is_canonical_url(via) && !via.include?(Protocol::DELIMITER) && !via.include?(Protocol::WRAPPER))
        return false
      end

      envelope_fields = [
        type,
        identifier,
        actor,
        via,
        Protocol::VERSION_TOKEN,
        Helpers.date_now,
        !signed_metadata.nil? && signed_metadata.size > 0 ? Signature.encode_metadata(signed_metadata) : '',
        '',
        message.to_s
      ]

      # Prepare the payload that is to be signed by cryptoSigner
      signer_payload = envelope_fields.join(Protocol::DELIMITER)

      # Make a copy of received unsignedMetadata that can be safely modified in-place by cryptoSigner
      unsigned_metadata_ref = Helpers.object_assign({}, unsigned_metadata)

      # Let the cryptoSigner sign the payload, and populate the unsignedMetadataRef if needed
      Helpers.log(config, :debug, 'Generating signature for payload', { signerPayload: signer_payload, unsignedMetadataRef: unsigned_metadata_ref })
      crypto_signatures = crypto_signer.call(signer_payload, unsigned_metadata_ref)

      # Replace the original message with cryptoSignatures in envelopeFields
      envelope_fields[8] = crypto_signatures.is_a?(Array) ? crypto_signatures.join(Protocol::DELIMITER) : crypto_signatures.to_s

      # Populate the unsignedMetadata in envelopeFields now (after signing)
      envelope_fields[7] = unsigned_metadata_ref.size > 0 ? Signature.encode_metadata(unsigned_metadata_ref) : ''

      # Construct the envelope of Signature by joining the items with ';' and wrapping everything in '|'
      return Protocol::WRAPPER + envelope_fields.join(Protocol::DELIMITER) + Protocol::WRAPPER
    end

    # Parses a raw signature envelope string.
    #
    # @param raw_data [String] the wrapped signature envelope.
    # @param config [Hash] optional overrides for the global Triauth.config settings. Defaults to `{}`.
    #
    # @raise [Triauth::Error] `invalid_signature` when the envelope or any of its fields is malformed.
    def initialize(raw_data, config = {})
      @config = Helpers.merge_config(config)

      # Pre-check the basic sanity and format of received arguments
      if !Helpers.is_string(raw_data) ||
         raw_data.length <= 3 ||
         (raw_data[0] != Protocol::WRAPPER || raw_data[-1] != Protocol::WRAPPER) ||
         Helpers.byte_size(raw_data) > Protocol::LIMITS[:signatureBytesize] ||
         raw_data.split(Protocol::WRAPPER, -1).length != 3
        raise Triauth::Error.new({ code: 'invalid_signature', reason: 'invalid', message: 'Invalid signature' })
      end

      @raw_data = raw_data

      # Extract information from the signature segment's envelope
      envelope = @raw_data[1...-1].split(Protocol::DELIMITER, -1)

      # A `shift` past the end of the envelope yields nil (JS: undefined), which every format check below refuses.
      @type = envelope.shift
      @identifier = envelope.shift
      @actor = envelope.shift
      @via = envelope.shift
      @ver = envelope.shift
      @ts = envelope.shift
      @encoded_signed_metadata = envelope.shift
      @encoded_unsigned_metadata = envelope.shift
      @crypto_signatures = envelope.dup

      # Check the format of data extracted from the envelope
      if !(!@type.nil? && @type != '' && Protocol::FLOWS.include?(@type)) ||
         !(!@identifier.nil? && @identifier != '' && Validator.validate_identifier(@identifier)[:valid]) ||
         !(@actor == '' || Validator.validate_identifier(@actor)[:valid]) ||
         !(!@via.nil? && @via != '' && Helpers.is_canonical_url(@via)) ||
         !(!@ver.nil? && @ver != '' && /\Av[1-9][0-9]{0,15}\z/.match?(@ver)) ||
         !(@ver == Protocol::VERSION_TOKEN) ||
         !(!@ts.nil? && @ts != '' && /\A[1-9][0-9]{0,15}\z/.match?(@ts)) ||
         !(@encoded_signed_metadata == '' || Helpers.is_base64url_string(@encoded_signed_metadata)) ||
         !(@encoded_unsigned_metadata == '' || Helpers.is_base64url_string(@encoded_unsigned_metadata)) ||
         @crypto_signatures.length < 1 || # there must be at least one crypto signature
         @crypto_signatures.any? { |cs| cs.length < 1 || !Helpers.is_base64url_string(cs) }
        raise Triauth::Error.new({ code: 'invalid_signature', reason: 'invalid', message: 'Invalid signature' })
      end

      # Parse the numeric properties from envelope - they have been pre-checked with regexp
      # (`parseInt` through a double: a 16-digit slot rounds above 2**53 exactly as JS does)
      @ver = Float(@ver[1..]).to_i
      @ts = Float(@ts).to_i

      # De-serialize metadata back to JS objects
      begin
        @signed_metadata   = @encoded_signed_metadata   != '' ? decode_metadata(@encoded_signed_metadata)   : {}
        @unsigned_metadata = @encoded_unsigned_metadata != '' ? decode_metadata(@encoded_unsigned_metadata) : {}
      rescue StandardError => err
        raise Triauth::Error.new({ code: 'invalid_signature', reason: 'invalid', message: 'Invalid signature' }, { cause: err })
      end
    end

    # Extracts object from encoded_metadata
    #
    # Triauth signature's envelope may contain additional information,
    # which can be either covered by the signatures (signedMetadata), or not (unsignedMetadata).
    #
    # @param encoded_metadata [String] A base64url encoded, JSON serialized object
    #
    # @return [Hash, Object] restored object
    def decode_metadata(encoded_metadata)
      return Helpers.safe_parse_json(
        Helpers.base64url_to_string(encoded_metadata)
      )
    end

    # Encodes an object into the encoded_metadata form carried by a signature envelope.
    #
    # The inverse of `decode_metadata`.
    #
    # @param metadata [Hash] An object to be carried in the envelope's signedMetadata or unsignedMetadata slot
    #
    # @return [String] a base64url encoded, JSON serialized representation of the object
    def self.encode_metadata(metadata)
      return Helpers.string_to_base64url(JSON.generate(metadata))
    end

    # Verifies that the signature segment is valid.
    #
    # @param message [String] Message, should be the same as originally signed.
    # @param constraints [Hash] Optional constraints that the signature must satisfy. Defaults to `{}`.
    # @option constraints [String] :type If given, must match the signature's `type` slot ('attest'|'auth'|'ping'|'sign'|'stamp').
    # @option constraints [String] :identifier If given, must match the identifier for which it was created.
    # @option constraints [String] :actor If given, must match the signature's `actor` slot — the delegate whose keys made the signature on behalf of the `identifier`; `''` requires a non-delegated signature.
    # @option constraints [Integer] :ver If given, must match the signature's protocol version.
    # @option constraints [String] :via If given, must match the URL of the client application that requested the signature.
    # @option constraints [Integer] :notBefore If given, must be a timestamp after which the signature was created.
    # @option constraints [Integer] :notAfter If given, must be a timestamp before which the signature was created.
    #
    # @return [Hash, false, nil] `{valid: true, type: String, identifier: String, identityDomain: String, lookupCode: String, actor: String, actorIdentityDomain: String, actorLookupCode: String, via: String, ver: Integer, signedAt: Integer, verifiedAt: Integer, publicProfile: Hash, groups: Array<String>, deviceName: String, deviceTag: String, keys: Array<Hash>, secure: Boolean, expires: (Integer, nil), signedMetadata: Hash, unsignedMetadata: Hash}`, false or nil:
    #   false upon failed verification, nil upon time constraints failure, or a Hash with the following properties:
    #   valid - set to true
    #   type - a type of signature that was verified
    #   identifier - the identifier for which the signature was made (the subject),
    #   identityDomain - the domain name under which the identifier's identity records are stored (the subject's, for delegated signatures; for a direct signature, the records the signing keys were read from),
    #   lookupCode - the lookup code the subject identity's domain derivation consumed (under `mode=private` its records live at a code-derived label), or `''` where no code was consumed - the same code the deviceTag carries as a `~` suffix,
    #   actor - the identifier of the delegate whose keys made the signature on behalf of the identifier, or `''` when the signature was made with the identifier's own keys,
    #   actorIdentityDomain - the domain name under which the actor's identity records are stored — the records the signing keys of a delegated signature were read from — or `''` when the signature was made with the identifier's own keys,
    #   actorLookupCode - the lookup code the actor's domain derivation consumed, or `''` where none was (an actor domain not running private mode, or a signature under the identifier's own keys),
    #   via - the URL of the client application that requested the signature,
    #   ver - the version slot of the signature envelope,
    #   signedAt - the device-asserted timestamp at which the signature was made (the envelope `ts` slot; the user's device clock, only proven to fall within the freshness window),
    #   verifiedAt - this host's wall-clock timestamp at which the signature's crypto was confirmed,
    #   publicProfile - a public profile of identifier as read from the DNS records,
    #   groups - fully-qualified group names the identifier's identity records claim membership in (e.g., ['admins@triauthdemo.org']), sorted and deduplicated; for delegated signatures these are the subject's groups, never the actor's,
    #   keys - an array of public keys, read from identity records, that were used for verification,
    #   deviceName - a user-given name of the device that was used for signing (the actor's device for delegated signatures),
    #   deviceTag - a string identifying the device; for delegated signatures the composite `<includeTag>:<actorIdentifier>:<actorDeviceTag>`, covering the grant (`include` statement) as well; under private mode a tag component carries the lookupCode as a `~<lookupCode>` suffix (`<deviceTag>~<lookupCode>` direct, `<includeTag>~<lookupCode>:<actor>:<deviceTag>` and/or `...:<deviceTag>~<actorLookupCode>` delegated),
    #   secure - a boolean, true only when DNSSEC was reported for the domain's triauth endpoint record and for every well-formed record of the signer's identity answer — and for delegated signatures, of the subject's too; a single non-validated identity record degrades it,
    #   expires - a timestamp when dns records from which keys were extracted expire (calculated from TTL values in DNS response; nil when none carried a TTL),
    #   signedMetadata - an object, containing any additional data that is covered by the embedded crypto signatures,
    #   unsignedMetadata - an object, containing data that for various reasons was not covered by the embedded crypto signatures, but may be needed to verify it
    #
    # @raise [Triauth::Error] `dns_unavailable` when DNS resolution of the signer's identity fails - intentionally propagated so that API methods report a retryable error instead of a false "signature invalid" verdict
    def verify(message, constraints = {})
      # Verify constraints to avoid bugs stemming from misspelling of keys in constraints object
      if !Helpers.has_only_known_properties(constraints, %i[type identifier actor ver via notBefore notAfter], false)
        Helpers.log(@config, :error, 'Unrecognized constraint')
        return false
      end

      # Make sure that we actually have signatures to verify
      if !(@crypto_signatures.length > 0)
        return false
      end

      # Fail closed if time bounds are provided in a non-numeric form rather than silently
      # coercing to NaN (which would compare as false and bypass the window check).
      if (!constraints[:notBefore].nil? && (!Helpers.is_number(constraints[:notBefore]) || (constraints[:notBefore].is_a?(Float) && constraints[:notBefore].nan?))) ||
         (!constraints[:notAfter].nil? && (!Helpers.is_number(constraints[:notAfter]) || (constraints[:notAfter].is_a?(Float) && constraints[:notAfter].nan?)))
        Helpers.log(@config, :error, 'Invalid notBefore/notAfter constraint')
        return false
      end

      # 3-state return contract (shared by Signature/MultiSignature/Response.verify and relied on by
      # every API method to choose between request_expired ("expired") and verification_failed ("invalid")):
      #   - a result object => success
      #   - `null`          => time-related failure ("expired")
      #   - `false`         => any other failure ("invalid")
      # `null` and `false` are deliberately distinct and must stay distinct as the value propagates up.
      if (!constraints[:notBefore].nil? && constraints[:notBefore] > @ts) ||
         (!constraints[:notAfter].nil? && constraints[:notAfter] < @ts)
        return nil
      end

      # All other constraint mismatches are generic failures.
      if (!constraints[:type].nil? && constraints[:type] != @type) ||
         (!constraints[:identifier].nil? && constraints[:identifier] != @identifier) ||
         (!constraints[:actor].nil? && constraints[:actor] != @actor) ||
         (!constraints[:ver].nil? && constraints[:ver] != @ver) ||
         (!constraints[:via].nil? && constraints[:via] != @via)
        return false
      end

      # Re-construct the envelope (payload) against which the signature will be verified.
      # envelopeFields[7] (the unsignedMetadata slot) is intentionally empty in the signed payload:
      # it is the ONE field of the envelope that is NOT cryptographically signed.
      envelope_fields = [
        @type,
        @identifier,
        @actor.nil? || @actor.empty? ? '' : @actor,
        @via,
        "v#{@ver}",
        @ts,
        @encoded_signed_metadata.nil? || @encoded_signed_metadata.empty? ? '' : @encoded_signed_metadata,
        '',
        message.to_s
      ]

      payload = envelope_fields.join(Protocol::DELIMITER)

      # Extract lookup codes that may be needed for mode == 'private' domains
      subject_lookup_code = Helpers.is_lookup_code(@signed_metadata[:lookupCode]) ? @signed_metadata[:lookupCode] : nil
      actor_lookup_code = Helpers.is_lookup_code(@signed_metadata[:actorLookupCode]) ? @signed_metadata[:actorLookupCode] : nil

      # Build the identity object for the identifier as embedded in the signature
      subject_identity = Identity.new(@identifier, { lookupCode: subject_lookup_code }, @config)
      actor_identity = @actor.nil? || @actor.empty? ? nil : Identity.new(@actor, { lookupCode: actor_lookup_code }, @config)
      signer_identity = actor_identity || subject_identity

      # Attempt to resolve identity records of the identifier. A definitive negative (domain not
      # configured for triauth, or no identity records published) fails the verification. A thrown
      # resolution error (e.g., TriauthError dns_unavailable on DNS failure) intentionally propagates instead.
      if !signer_identity.resolve
        Helpers.log(@config, :debug, 'Identifier does not exist or is not configured for triauth')
        return false
      end

      # Prepare a context for this check
      context = {
        mode: @type,                                                              # signature type ('auth'|'sign'|'stamp'|'ping'|'attest') — enforces the key's "use" option
        webAuthnOrigin: "https://#{signer_identity.authentication_endpoint.host}" # for WebAuthn verifications - clientData.origin must equal the RESOLVED authentication endpoint origin (the host the Authenticator is actually served from, e.g. https://auth.example.com), NOT the identifier's domain; the endpoint record grammar fixes the endpoint scheme to https with no port, so the origin is exactly this concatenation
      }

      kv_result = signer_identity.keys.verify(payload, @crypto_signatures, context, @signed_metadata, @unsigned_metadata)
      if !kv_result || kv_result[:valid] != true
        return false
      end

      device_tag = kv_result[:tag]
      secure = signer_identity.secure # DNSSEC status is resolution-level - any non-validated identity record degrades it
      expires = Helpers.earliest(signer_identity.authentication_endpoint.expires, kv_result[:expires]) # the endpoint record selects the keys, so it bounds their freshness

      # For delegated signatures (with actor set), now make sure that the proper include is present in the main identity records
      # (covering the actor, the flow, and - through its `scope` - the service the signature was made via),
      # and update the `secure`, `expires`, and `deviceTag` with information from it.
      if !actor_identity.nil?

        # Resolve the main identity for which the signature was made
        if !subject_identity.resolve
          Helpers.log(@config, :debug, 'Main identifier does not exist or is not configured for triauth')
          return false
        end

        include_statement = subject_identity.includes.find(actor_identity, nil, @type, Helpers.url_host(@via))

        # Make sure the include statement is present
        if !include_statement
          Helpers.log(@config, :debug, 'No matching include statements found for this actor')
          return false
        end

        # Device tag for delegated signatures is the ':' joined: include record tag, actor identifier, and actor's deviceTag,
        # e.g., '5I4NnX-4lW3gdTqGW3zKpLsLR9oRiWip8zp6mqQgkL4:actor@triauthdemo.org:3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ'.
        # We need all of this so that deviceTag is guaranteed to change when:
        # - any significant changes to the `include` statement were made (e.g., change in `use` or `scope`),
        # - any significant changes to actor's identity domain configuration (e.g., a lookup code rotation) were made,
        # - and any changes to actor's device keys were made.
        # Also, the full actor's identifier in the deviceTag allows for simpler 'Triauth.check' code.
        # (The JS declares block-scoped constants that shadow the two lookup codes above; Ruby has no block scope
        # for `if`, so the locals are reassigned - the earlier values are not read again.)
        subject_lookup_code = subject_identity.identity_domain.lookup_code
        actor_lookup_code = actor_identity.identity_domain.lookup_code

        device_tag =
          include_statement[:tag] + (subject_lookup_code.nil? || subject_lookup_code.empty? ? '' : "~#{subject_lookup_code}") +
          ":#{actor_identity.identifier}:" +
          device_tag + (actor_lookup_code.nil? || actor_lookup_code.empty? ? '' : "~#{actor_lookup_code}")

        secure &&= subject_identity.secure
        expires = Helpers.earliest(expires, Helpers.earliest(subject_identity.authentication_endpoint.expires, include_statement[:expires]))

      elsif !(subject_identity.identity_domain.lookup_code.nil? || subject_identity.identity_domain.lookup_code.empty?)
        device_tag += "~#{subject_identity.identity_domain.lookup_code}"

      end

      # Wall-clock instant at which this signature was confirmed
      verified_at = Helpers.date_now

      return {
        valid: true,
        type: @type,
        identifier: subject_identity.identifier,
        identityDomain: subject_identity.identity_domain.domain_name,
        lookupCode: subject_identity.identity_domain.lookup_code.nil? || subject_identity.identity_domain.lookup_code.empty? ? '' : subject_identity.identity_domain.lookup_code,
        actor: actor_identity.nil? ? '' : actor_identity.identifier,
        actorIdentityDomain: actor_identity.nil? ? '' : actor_identity.identity_domain.domain_name,
        actorLookupCode: actor_identity.nil? || actor_identity.identity_domain.lookup_code.nil? || actor_identity.identity_domain.lookup_code.empty? ? '' : actor_identity.identity_domain.lookup_code,
        via: @via,
        ver: @ver,
        signedAt: @ts,
        verifiedAt: verified_at,
        publicProfile: subject_identity.public_profile,
        groups: subject_identity.groups,
        deviceName: kv_result[:name],
        deviceTag: device_tag,
        keys: kv_result[:keys],
        secure: secure,
        expires: expires,
        signedMetadata: @signed_metadata,
        unsignedMetadata: @unsigned_metadata
      }
    end
  end
end
