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
require_relative 'helpers'
require_relative 'protocol'

module Triauth
  # A collection of helper methods dedicated for data validation.
  #
  # These validation methods are not meant to be bullet-proof, and API method calls should return correct results even
  # if invalid or dangerous data for some reason passes the validation.
  class Validator
    # The longest well-formed session key, `<domain>:<key>` with a domain of at most LIMITS.domainNameBytesize
    # bytes and a 43-character key, and the longest well-formed device tag, `<grantTag>:<actorIdentifier>:<actorDeviceTag>`
    # with two tag components of 43 + 1 + 16 characters around an identifier of at most LIMITS.identifierBytesize bytes.
    # The validators compare the length against these caps ahead of any split, so the cost of a rejection does not
    # grow with the input.
    SESSION_KEY_MAX_LENGTH = Protocol::LIMITS[:domainNameBytesize] + 1 + 43
    DEVICE_TAG_MAX_LENGTH = (2 * (43 + 1 + 16)) + 2 + Protocol::LIMITS[:identifierBytesize]
    private_constant :SESSION_KEY_MAX_LENGTH, :DEVICE_TAG_MAX_LENGTH

    # The message of every validation error, by error code and reason. Each code names the invalid field,
    # and each reason names the rule that the field breaks.
    ERRORS = {
      'invalid_identifier' => {
        'invalid' => 'Identifier is invalid',
        'empty' => 'Identifier must not be empty',
        'too_long' => 'Identifier is too long',
        'not_lowercase' => 'Identifier must be provided in lowercase',
        'invalid_format' => 'Identifier must include one @ sign',
        'invalid_username' => 'Identifier contains invalid username',
        'invalid_domain' => 'Identifier contains invalid domain name'
      },
      'invalid_callback_url' => { 'invalid' => 'Invalid callbackUrl' },
      'invalid_ext' => { 'invalid' => 'Invalid ext' },
      'invalid_challenge' => { 'invalid' => 'Invalid challenge' },
      'invalid_response' => { 'invalid' => 'Invalid response' },
      'invalid_signature' => { 'invalid' => 'Invalid signature' },
      'invalid_session_key' => { 'invalid' => 'Invalid session key' },
      'invalid_message' => { 'invalid' => 'Invalid message' },
      'invalid_attachments' => { 'invalid' => 'Invalid attachments' },
      'invalid_attestations' => { 'invalid' => 'Invalid attestations' },
      'invalid_lookup_code' => { 'invalid' => 'Invalid lookup code' },
      'invalid_device_tag' => { 'invalid' => 'Invalid device tag' },
      'invalid_device_name' => {
        'invalid' => 'Device name is invalid',
        'empty' => 'Device name must not be empty',
        'too_long' => 'Device name is too long',
        'not_lowercase' => 'Device name must be provided in lowercase',
        'invalid_characters' => 'Device name must include only letters, numbers, and hyphens'
      },
      'invalid_group_name' => {
        'invalid' => 'Group name is invalid',
        'empty' => 'Group name must not be empty',
        'too_long' => 'Group name is too long',
        'not_lowercase' => 'Group name must be provided in lowercase',
        'invalid_characters' => 'Group name must include only letters, numbers, and hyphens'
      }
    }
    private_constant :ERRORS

    # Builds a validation result from the reasons found for one field.
    #
    # @param code [String] The error code of the field (e.g., `invalid_identifier`).
    # @param reasons [Array<String>] The reasons found, empty when the field is valid.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.expand_result(code, reasons)
      return {
        valid: reasons.length == 0,
        errors: reasons.map { |reason| { code: code, reason: reason, message: ERRORS[code][reason] } }
      }
    end
    private_class_method :expand_result

    # Validates the provided personal identifier's format, and returns human-friendly error messages if problems are found.
    #
    # @param identifier [String] Identifier that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_identifier(identifier)
      if !Helpers.is_string(identifier)
        return expand_result('invalid_identifier', ['invalid'])
      end

      if identifier.length <= 0
        return expand_result('invalid_identifier', ['empty'])
      end

      if identifier.length > Protocol::LIMITS[:identifierBytesize] || Helpers.byte_size(identifier) > Protocol::LIMITS[:identifierBytesize]
        return expand_result('invalid_identifier', ['too_long'])
      end

      # identifiers must not contain any whitespace characters and/or NULL
      if /[#{Helpers::JS_WS}\0]/o.match?(identifier)
        return expand_result('invalid_identifier', ['invalid'])
      end

      if identifier != identifier.downcase
        return expand_result('invalid_identifier', ['not_lowercase'])
      end

      if identifier.scan(/@/).length != 1
        return expand_result('invalid_identifier', ['invalid_format'])
      end

      username, domain = identifier.split('@', -1)
      reasons = []

      # Username may be composed only of ASCII letters, numbers, dot and hyphen signs, must start with a letter or a digit,
      # and must be no longer than 63 chars (DNS label limit),
      if !/\A[a-z0-9][a-z0-9.-]{0,62}\z/.match?(username) ||

         # consecutive dots and/or hyphens are not allowed,
         /[.-][.-]/.match?(username) ||

         # and it must not end with a dot or hyphen.
         /[.-]\z/.match?(username)
        reasons.push('invalid_username')
      end

      if !Helpers.is_domain_name(domain)
        reasons.push('invalid_domain')
      end

      return expand_result('invalid_identifier', reasons)
    end

    # Validates the provided callback URL's format, and returns human-friendly error messages if problems are found.
    #
    # @param callback_url [String] Callback URL that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_callback_url(callback_url)
      reasons = []

      # A callback URL is any canonical URL — http or https, named or IPv4-literal host — whose
      # base URL is free of the signature-envelope delimiter ';'
      base = Helpers.get_base_url(callback_url)
      if base == false || base.include?(Protocol::DELIMITER)
        reasons.push('invalid')
      end

      return expand_result('invalid_callback_url', reasons)
    end

    # Validates the optional `ext` property for `Triauth.authenticate` — both as supplied in stage 1 and as received back in stage 3.
    #
    # `ext` must be a plain object whose values are strings, whole numbers, booleans, or plain objects one level deep (no arrays, no deeper nesting).
    # A string value carries no unpaired surrogate and a number is a whole number of magnitude at most 2^53 - 1, the rules that
    # `Helpers.safe_parse_json` applies to every JSON value when the ext comes back in stage 3.
    # Keys must additionally be ASCII-only — `Helpers.safe_parse_json` rejects non-ASCII property names when the ext round-trips back in stage 3 —
    # and never one of the prototype-poisoning names (`__proto__`, `constructor`, `prototype`)
    #
    # @param ext [Hash] Ext object that should be validated.
    # @param depth [Integer] Nesting depth of the object being validated: 0 for the `ext` object itself,
    #                        1 for the single level of nested plain objects that `ext` values may contain (defaults to 0).
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_ext(ext, depth = 0)
      reasons = []

      if ext.nil? ||
         !(ext.is_a?(Hash) && ext.keys.all? { |k| Helpers.is_normal_string(k.to_s, Protocol::LIMITS[:jsonMaxKeyLength]) && !/[^\x20-\x7E]/.match?(k.to_s) && !%w[__proto__ constructor prototype].include?(k.to_s) } && ext.values.all? { |e| (Helpers.is_string(e) && Helpers.is_well_formed_string(e)) || Helpers.is_safe_integer(e) || e == true || e == false || (depth == 0 && validate_ext(e, depth + 1)[:errors].length == 0) }) ||
         Helpers.byte_size(JSON.generate(ext)) > Protocol::LIMITS[:extBytesize]
        reasons.push('invalid')
      end

      return expand_result('invalid_ext', reasons)
    end

    # Validates the `attestations` option for `Triauth.attest`, applied both when building the challenge (stage 1) and verifying the response (stage 3).
    #
    # `attestations` must be a plain object keyed by attestation name, where each value is `{label: string, providers: string[]}`.
    # An empty object `{}` is valid; passing it will produce `{attested: true, attestations: {}}` from stage 3.
    # An attestation name is printable ASCII, as it becomes a property name of the challenge that `Helpers.safe_parse_json` admits only in ASCII in stage 3,
    # and never one of the prototype-poisoning keys (`__proto__`, `constructor`, `prototype`).
    #
    # @param attestations [Hash] Attestations object that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_attestations(attestations)
      reasons = []

      if attestations.nil? ||
         !attestations.is_a?(Hash) ||
         !attestations.keys.all? { |k| Helpers.is_normal_string(k.to_s) && !/[^\x20-\x7E]/.match?(k.to_s) && !%w[__proto__ constructor prototype].include?(k.to_s) }
        return expand_result('invalid_attestations', ['invalid'])
      end

      # The multi-signature envelope holds at most maxMultiSignatures entries (1 user + N attesters),
      # so requesting more than (maxMultiSignatures - 1) attestations creates a request that can never be satisfied.
      if attestations.size > Protocol::LIMITS[:maxMultiSignatures] - 1
        return expand_result('invalid_attestations', ['invalid'])
      end

      attestations.each_value do |entry|
        if !entry.is_a?(Hash) || # `entry !== null && typeof entry === 'object' && !Array.isArray(entry)`: a Hash, so a nil entry is invalid here as there
           !entry.keys.all? { |k| %i[label providers].include?(k) } ||
           !Helpers.is_normal_string(entry[:label]) ||
           !(
             entry[:providers].is_a?(Array) &&
             entry[:providers].length > 0 && entry[:providers].length <= Protocol::LIMITS[:maxMultiSignatures] - 1 &&
             entry[:providers].all? { |p_url| Helpers.is_secure_url(p_url) }
           )
          reasons.push('invalid')

        else
          entry[:providers].each do |provider_url|
            # Beyond being canonical on a secure origin, a provider URL is displayed verbatim in
            # the authenticator UI and embedded whole as the `via` field of the attestation
            # segment, so it must carry no query, no fragment, no percent-escapes, no envelope
            # delimiter ';', and no apostrophe. In a canonical URL, '?' and '#' can appear only
            # as the query/fragment introducers and '%' only in an escape — one charset test
            # covers every excluded character.
            if /[?#%;']/.match?(provider_url)
              reasons.push('invalid')
            end
          end
        end
      end

      return expand_result('invalid_attestations', reasons)
    end

    # Validates the challenge string returned from stage 1 of an authentication flow, before passing it to stage 3.
    #
    # The challenge must be a non-empty base64url-encoded string within the allowed byte size.
    #
    # @param challenge [String] Challenge string that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_challenge(challenge)
      reasons = []

      if !Helpers.is_string(challenge) ||
         challenge.length <= 0 ||
         challenge.length > Protocol::LIMITS[:challengeBytesize] ||
         Helpers.byte_size(challenge) > Protocol::LIMITS[:challengeBytesize] ||
         !Helpers.is_base64url_string(challenge)
        reasons.push('invalid')
      end

      return expand_result('invalid_challenge', reasons)
    end

    # Validates the response string returned by the authenticator in stage 3 of an authentication flow.
    #
    # The response must be a pipe-delimited string of the form `|...|`, within the allowed byte size.
    #
    # @param response [String] Response string that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_response(response)
      reasons = []

      if !Helpers.is_string(response) ||
         response.length <= 3 ||
         (response[0] != '|' || response[-1] != '|') ||
         response.length > Protocol::LIMITS[:signatureBytesize] ||
         Helpers.byte_size(response) > Protocol::LIMITS[:signatureBytesize]
        reasons.push('invalid')
      end

      return expand_result('invalid_response', reasons)
    end

    # Validates the sealed response received in stage 3 of an authentication flow, before it is opened.
    #
    # A sealed response is `<enc>.<ciphertext>`, both base64url: an 87-character encapsulated key, and a ciphertext of
    # at least the 16-byte authentication tag, bounded by the sealed size of the largest response envelope.
    #
    # @param response [String] Sealed response that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_sealed_response(response)
      reasons = []
      max_length = 87 + 1 + ((Protocol::LIMITS[:signatureBytesize] + 16) * 4).fdiv(3).ceil # `Math.ceil(... * 4 / 3)`: a real division, never the Integer `/`

      if !Helpers.is_string(response) ||
         response.length > max_length || # code points where JS counts UTF-16 units: a string the two counts disagree on is non-ASCII and invalid at the regex either way
         !/\A[A-Za-z0-9_-]{87}\.[A-Za-z0-9_-]{22,}\z/.match?(response)
        reasons.push('invalid')
      end

      return expand_result('invalid_response', reasons)
    end

    # Validates the message string to be signed or stamped in a `Triauth.sign` or `Triauth.stamp` flow.
    #
    # @param message [String] Message that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_message(message)
      reasons = []

      if !Helpers.is_normal_string(message, Protocol::LIMITS[:messageBytesize])
        reasons.push('invalid')
      end

      return expand_result('invalid_message', reasons)
    end

    # Validates the `attachments` array for a `Triauth.sign` flow.
    #
    # Each attachment must be a plain object with `name` (string) and `sha256` (64-character lowercase hex string),
    # plus a `sourceUrl` (a canonical URL). Names must be unique within the array.
    #
    # `sourceUrl` is only needed when building the challenge (stage 1), so the authenticator knows where to fetch
    # the file to hash. It is intentionally NOT required on the signed response (stage 3): the durable proof binds
    # only `name`+`sha256`, and keeping `sourceUrl` out of the signed payload avoids embedding fetch URLs (which may
    # carry presigned credentials) in a portable, third-party-verifiable signature. Pass `require_source_url = false`
    # to validate a response's attachments, where `sourceUrl` may be omitted (but is held to the same rule if present).
    #
    # @param attachments [Array<Hash>] Attachments array that should be validated (each entry `{name: String, sourceUrl?: String, sha256: String}`).
    # @param require_source_url [Boolean] Whether a valid `sourceUrl` is mandatory on every entry (defaults to true).
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_attachments(attachments, require_source_url = true)
      reasons = []
      seen_names = {} # a dedup set keyed by the attachment name Strings (the port of `Object.create(null)`)

      if !attachments.is_a?(Array) ||
         attachments.length > Protocol::LIMITS[:attachmentsCount] ||
         !attachments.all? do |f|
           Helpers.has_only_known_properties(f, %i[name sourceUrl sha256]) &&
           Helpers.is_normal_string(f[:name], 255) &&
           ((!require_source_url && !f.key?(:sourceUrl)) || Helpers.is_canonical_url(f[:sourceUrl])) && # `=== undefined` is "member absent" (`key?`); a present nil member keeps the JS null outcome (rejected)
           Helpers.is_string(f[:sha256]) && /\A[0-9a-f]{64}\z/.match?(f[:sha256]) &&
           !seen_names[f[:name]] && (seen_names[f[:name]] = true)
         end
        reasons.push('invalid')
      end

      return expand_result('invalid_attachments', reasons)
    end

    # The binder names a signature may state inside its signed-metadata `bind` object: the verified
    # fields the signature is bound to. Each names a field of the verified user signature and must
    # equal it (see `Triauth.attest`).
    #
    # @return [Array<Symbol>]
    BINDER_NAMES = %i[identifier via deviceTag].freeze

    # Validates a signature segment's signed metadata against the binder grammar.
    #
    # A signature states what it is bound to in the `bind` object, and **every member of `bind` is
    # critical**: a verifier must recognize it and it must match, so a constraint the producer signed
    # can never be dropped without a trace. Members outside `bind` stay auxiliary and tolerant
    # (an unrecognized one is ignored), so a compatible revision may still add signed metadata.
    #
    # @param signed_metadata [Hash] The signed metadata of a signature segment.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    #          Invalid (`invalid_signature`) when `bind` is present but is not an object of at least one recognized
    #          binder with a string value.
    def self.validate_binders(signed_metadata)
      if !signed_metadata.key?(:bind)
        return expand_result('invalid_signature', []) # a signature that binds nothing is valid - attesters attest anonymously
      end

      bind = signed_metadata[:bind]
      binders = bind.is_a?(Hash) ? bind.keys : nil

      if binders.nil? ||
         binders.length < 1 ||
         !binders.all? { |binder| BINDER_NAMES.include?(binder) && Helpers.is_string(bind[binder]) }
        return expand_result('invalid_signature', ['invalid'])
      end

      return expand_result('invalid_signature', [])
    end

    # Validates the `sessionKey` that gates stage 1 of `Triauth.ping`, `Triauth.sign`, `Triauth.stamp`, and `Triauth.attest`.
    #
    # A session key is the `sessionKey` of a `Triauth.authenticate` result, 32 bytes in 43 base64url characters.
    # After a delegated sign-in it is `<domain>:<key>`, with the lowercase domain name of the actor.
    #
    # @param session_key [String] Session key that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_session_key(session_key)
      parts = if Helpers.is_string(session_key) && session_key.length <= SESSION_KEY_MAX_LENGTH
                session_key.empty? ? [''] : session_key.split(':', -1) # JS `''.split(':')` is `['']` where Ruby gives `[]`
              else
                []
              end
      domain, key = parts.length == 2 ? parts : [nil, parts[0]]

      if parts.length < 1 || parts.length > 2 ||
         (!domain.nil? && !(Helpers.is_domain_name(domain) && domain == domain.downcase)) ||
         key.length != 43 || !Helpers.is_base64url_string(key)
        return expand_result('invalid_session_key', ['invalid'])
      end

      # The canonical base64url of 32 bytes has no data in the unused bits of its last character
      begin
        Helpers.base64url_to_uint8(key)
      rescue StandardError
        return expand_result('invalid_session_key', ['invalid'])
      end

      return expand_result('invalid_session_key', [])
    end

    # Validates the provided device name's format, and returns human-friendly error messages if problems are found.
    #
    # Device names must be lowercase and composed of letters, numbers, and single hyphens between alphanumerics
    # (no leading, trailing, or consecutive hyphens), within the allowed byte size.
    #
    # @param device_name [String] Device name that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_device_name(device_name)
      return expand_result('invalid_device_name', name_errors(device_name))
    end

    # Validates the provided group name's format, and returns human-friendly error messages if problems are found.
    #
    # Group names follow the device-name grammar: lowercase letters, numbers, and single hyphens between alphanumerics
    # (no leading, trailing, or consecutive hyphens), within the allowed byte size. The name is the bare name as published
    # in a `groups` record (e.g., `admins`), not the fully-qualified form found in results (e.g., `admins@example.com`).
    #
    # @param group_name [String] Group name that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_group_name(group_name)
      return expand_result('invalid_group_name', name_errors(group_name))
    end

    # Validates the provided lookup code's format.
    #
    # A lookup code is exactly 16 uppercase letters and digits (e.g., `K7QJ3FB9M2WZX0C4`). It addresses the records
    # of an identity under a `mode=private` domain.
    #
    # @param lookup_code [String] Lookup code that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_lookup_code(lookup_code)
      reasons = []

      if !Helpers.is_lookup_code(lookup_code)
        reasons.push('invalid')
      end

      return expand_result('invalid_lookup_code', reasons)
    end

    # Validates the provided device tag's format.
    #
    # A device tag is the `deviceTag` of a result: a 43-character base64url digest (e.g., `3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ`),
    # suffixed with `~` and a lookup code under a `mode=private` domain. After a delegated sign-in it is
    # `<grantTag>:<actorIdentifier>:<actorDeviceTag>`, and each of its two tags may carry such a suffix.
    #
    # @param device_tag [String] Device tag that should be validated.
    #
    # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason: String, message: String}>}`
    def self.validate_device_tag(device_tag)
      reasons = []
      parts = Helpers.is_string(device_tag) && device_tag.length <= DEVICE_TAG_MAX_LENGTH ? device_tag.split(':', -1) : [] # JS `''.split(':')` is `['']` where Ruby gives `[]`: neither is 1 or 3 parts

      if !(parts.length == 1 && is_reported_tag(parts[0])) &&
         !(parts.length == 3 && is_reported_tag(parts[0]) && validate_identifier(parts[1])[:valid] && is_reported_tag(parts[2]))
        reasons.push('invalid')
      end

      return expand_result('invalid_device_tag', reasons)
    end

    # Checks one tag component of a device tag: a 43-character base64url digest, optionally suffixed with `~` and a lookup code.
    #
    # @param component [String] Tag component that should be checked.
    #
    # @return [Boolean] true when the component is a well-formed tag
    def self.is_reported_tag(component)
      tag, lookup_code, *rest = component.empty? ? [''] : component.split('~', -1) # JS `''.split('~')` is `['']` where Ruby gives `[]`

      if rest.length > 0 || tag.length != 43 || (!lookup_code.nil? && !Helpers.is_lookup_code(lookup_code))
        return false
      end

      # The canonical base64url of a 32-byte digest has no data in the unused bits of its last character
      begin
        Helpers.base64url_to_uint8(tag)
      rescue StandardError
        return false
      end

      return true
    end
    private_class_method :is_reported_tag

    # Checks a name against the device-name grammar, shared by device names and group names.
    #
    # @param name [Object] Name that should be validated.
    #
    # @return [Array<String>] The reasons found, empty when the name is valid.
    def self.name_errors(name)
      reasons = []

      if !Helpers.is_string(name)
        return ['invalid']
      end

      if name.length <= 0
        reasons.push('empty')
      end

      if name.length > Protocol::LIMITS[:deviceNameBytesize] || Helpers.byte_size(name) > Protocol::LIMITS[:deviceNameBytesize]
        return ['too_long']
      end

      # The name must not contain any whitespace characters and/or NULL
      if /[#{Helpers::JS_WS}\0]/o.match?(name)
        reasons.push('invalid')
      end

      if name != name.downcase
        reasons.push('not_lowercase')
      end

      # Lowercase alphanumerics joined by single hyphens: the name must start and end on an alphanumeric
      # and carry no consecutive hyphens.
      if !/\A[a-z0-9]+(-[a-z0-9]+)*\z/.match?(name)
        reasons.push('invalid_characters')
      end

      return reasons
    end
    private_class_method :name_errors
  end
end
