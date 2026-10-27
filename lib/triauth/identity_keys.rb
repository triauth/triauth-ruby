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
require_relative 'validator'
require_relative 'protocol'
require_relative 'verifiers'

module Triauth
  # Holds information about devices and their public keys that belong to the identifier, as extracted from identity records.
  class IdentityKeys
    # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
    attr_reader :config
    # The key groups (devices) published for the identity, keyed by device name (a Symbol).
    # Only groups marked `valid:true` can be used; a tainted group can never become valid.
    # @return [Hash{Symbol => Hash}] each group `{keyCount: Integer, keys: Array<{value: String, options: Hash}>, expires: (Integer, nil), tainted: (Boolean, nil), valid: (Boolean, nil), tag: (String, nil)}`
    attr_reader :key_groups
    # The total number of valid key groups (devices).
    # @return [Integer]
    attr_reader :count

    # Constructs a new, empty instance of IdentityKeys; key groups are populated through `add`.
    #
    # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
    def initialize(config = {})
      @config = Helpers.merge_config(config)

      @key_groups = {}

      @count = 0
    end

    # Adds a key to the correct group of identity keys
    #
    # @param key_data [String] the value of the key as visible in the identity record that includes the prefix with device name and key index
    # @param options [Hash] the key options as specified in the identity record; recognized critical options are
    #        `type` (a registered verifier type), `use` (comma-separated list of allowed modes),
    #        and `uv=required` (demand user verification; valid only on `webauthn-*` typed keys) - any other non-`x-` option or value taints the keyGroup. Defaults to `{}`.
    # @param key_metadata [Hash] the metadata about the key record, as passed from the DNS resolver. Defaults to `{}`.
    # @return [Boolean] true when key was successfully added, false if there are problems with the key structure (e.g., invalid group index)
    def add(key_data, options = {}, key_metadata = {})
      # Work on a private copy of `options`. `Helpers.object_assign` copies a `__proto__` key as data, so the options
      # schema below judges it like any other unknown option
      options = Helpers.object_assign({}, options)

      # an ill-formed (invalid UTF-8) `key_data` raises here, as a non-string does in JS; records reach this method `is_normal_string`-validated
      match_data = key_data.match(%r{\A(?<deviceName>[a-z0-9-]{1,20})\[(?<keyIdx>[0-9]{1,6})/(?<keyCount>[0-9]{1,6})\]:(?<keyVal>#{Helpers::JS_NOT_WS}+)\z}o)

      if match_data.nil?
        Helpers.log(@config, :debug, 'Ignoring key due to unrecognized syntax')
        return false
      end

      # At this point we know that deviceName conforms to the required syntax, but everything else needs additional validation.
      # We intentionally let through things like non-base64-url keyVals, as when invalid, they should taint the whole keyGroup.

      device_name = match_data[:deviceName]

      # Map leading-zero forms (e.g., "01") to literal 0 so they fail the downstream range check
      # and taint the whole keyGroup, rather than being silently skipped at the regex stage.
      # Skipping would leave the device's other published keys potentially usable, which we don't
      # want when any single record on that device looks malformed.
      key_idx = match_data[:keyIdx][0] == '0' ? 0 : Integer(match_data[:keyIdx], 10)
      key_count = match_data[:keyCount][0] == '0' ? 0 : Integer(match_data[:keyCount], 10)
      key_val = match_data[:keyVal]

      max_devices, max_keys_per_device = Protocol::LIMITS.values_at(:maxDevices, :maxKeysPerDevice)

      # Make sure device name conforms to the requirements
      if !Validator.validate_device_name(device_name)[:valid]
        Helpers.log(@config, :debug, 'Ignoring key due to invalid device name')
        return false
      end

      # `keyGroups` is keyed by the device name as a Symbol (the profile's key rule)
      device_key = device_name.to_sym

      # Make sure we are under the maxDevices limit which is the same as the number of defined keyGroups
      if @key_groups[device_key].nil? && @key_groups.size >= max_devices
        Helpers.log(@config, :debug, "Too many devices defined, ignoring key for device #{device_name}")
        return false
      end

      # Pre-initialize the entry with defaults
      @key_groups[device_key] ||= { keyCount: key_count, keys: [], expires: nil }

      key_group = @key_groups[device_key]

      # Parse options

      # All non-x- prefixed options are critical, and unknown critical options MUST taint the keyGroup
      options_schema = {
        type: Triauth::Verifiers.list,
        use: [Protocol::FLOWS_USE_REGEXP],
        uv: ['required']
      }

      # Set defaults
      options[:type] = 'es256' if options[:type].nil?
      options[:use] = Protocol::FLOWS.join(',') if options[:use].nil?

      # Validate options
      options_tainted = !Helpers.verify_options_schema(options, options_schema)

      # The `uv` (user verification) constraint can only be proven by WebAuthn-backed keys - on any
      # other key type the requirement would be silently unenforceable, so it taints the keyGroup instead.
      # (`options['uv'] !== undefined`: a present `uv` member, nil included, takes this branch; `RegExp.test` coerces a
      # non-string `type` to text and never matches `webauthn-`, so a non-string `type` taints here as in JS)
      if options.key?(:uv) && !(Helpers.is_string(options[:type]) && /\Awebauthn-/.match?(options[:type]))
        options_tainted = true
      end

      # Catch edge cases, mark keyGroups as tainted, and return false
      # (the slot test runs only after `key_idx >= 1` held, so `keys[-1]` is never read)
      if key_group[:tainted] ||
         options_tainted ||                                     # options are tainted (invalid options)
         (key_count < 1 || key_count > max_keys_per_device) ||  # there are too many keys per device/keyGroup
         (key_idx < 1 || key_idx > key_count) ||                # key index is mangled - e.g., [6/5]
         key_group[:keyCount] != key_count ||                   # number of keys in the group is not consistent across all keys (e.g., laptop[1/10], and then laptop[2/5])
         !key_group[:keys][key_idx - 1].nil? ||                 # key entry with the given index is doubled (e.g., laptop[1/2]:aaa, laptop[1/2]:bbb)
         key_val.length > 1024 ||                               # key value must be of sane length
         !Helpers.is_base64url_string(key_val)                  # key value must be base64URL encoded

        # Mark the keyGroup as tainted, so that it cannot become valid
        key_group[:tainted] = true

        # If for some reason the keyGroup has been previously marked as valid and counted in, un-validate it
        if key_group[:valid]
          key_group[:valid] = false
          key_group.delete(:tag)
          @count -= 1
        end

        # Return false to let the caller know that the key was not added
        Helpers.log(@config, :debug, 'Key failed validation and tainted all keys for device', { keyData: key_data, deviceName: device_name })
        return false
      end

      # At this point key has been validated, so we can continue

      # Store the key in the keyGroup at the appropriate index (the Array grows with nil slots: the JS sparse array)
      key_group[:keys][key_idx - 1] = {
        value: key_val,
        options: options
      }

      # The group expiry timestamp is calculated as min of expiry timestamps of individual keys
      # If no key in keyGroup has expires set, the keyGroup.expires stays nil
      # (number truthiness: a nil or 0 `expires` is absent, as in `keyMetadata.expires &&` and `keyGroup.expires || Infinity`)
      expires = key_metadata[:expires]
      if !expires.nil? && expires != 0 && expires < (key_group[:expires].nil? || key_group[:expires] == 0 ? Float::INFINITY : key_group[:expires])
        key_group[:expires] = expires
      end

      populated_key_count = key_group[:keys].count { |k| !k.nil? } # `Object.keys(sparseArray).length`: the populated slots

      # If we have all keys from the group, and it was not tainted, we can mark it as valid and calculate its tag
      # The tag takes into account only options that do not start with 'x-'
      if !key_group[:tainted] && key_group[:keyCount] == populated_key_count && populated_key_count > 0
        key_group[:valid] = true
        key_group[:tag] = Helpers.sha256(
          # `Object.entries(sparseArray)` yields the string index and the populated slots, in index order
          "\x01#{device_name}\x1E#{key_group[:keyCount]}\x02" +
          key_group[:keys].each_with_index.reject { |key, _| key.nil? }.map do |key, idx|
            [
              idx.to_s,
              key[:value],
              *key[:options].reject { |k, _| k.to_s[0] == 'x' && k.to_s[1] == '-' }.map { |k, v| "#{k}=#{v}" }.sort
            ].join("\x1E")
          end.join("\x1D")
        )
        @count += 1
      end

      return true
    end

    # Finds a key group that matches the given tag.
    #
    # @param tag [String] The device tag to look for, as carried by a signature envelope.
    #
    # @return [Hash, nil] the matching key group (`{keyCount: Integer, keys: Array<{value: String, options: Hash}>, expires: (Integer, nil), tainted: (Boolean, nil), valid: (Boolean, nil), tag: (String, nil)}`),
    #         or nil when no valid group carries that tag
    def find_by_tag(tag)
      Helpers.ordered_entries(@key_groups).map { |_, key_group| key_group }.each do |key_group| # `Object.values(this.keyGroups)`: the values in the JS object key order
        if key_group[:valid] && key_group[:tag] == tag
          return key_group
        end
      end

      return nil
    end

    # Verifies that the given signatures are valid for the given message and given key use constraint -
    # i.e., that they were made using private keys for which a matching set of public keys are present
    # in one key group of this identity keys, and such keys are marked for such use.
    #
    # Signatures are verified using verifiers defined under the Triauth::Verifiers namespace, that may be specific
    # for each of the identity keys (as loaded from the DNS), and specified in the key's "type" option. For example,
    # for the identity key visible in DNS as "key BHA...QPDR type=ecdsa", an "ECDSA" - Triauth::Verifiers::Ecdsa verifier will be used.
    #
    # Signatures must match all keys in a key group for the verification to be successful.
    #
    # @param message [String] The message (envelope payload) for which the signatures are verified.
    # @param signatures [Array<String>] Crypto signatures (base64url) to attempt to verify against the key group's keys.
    # @param context [Hash] Verification context (`{mode: String, webAuthnOrigin: (String, nil)}`).
    #        `mode` (typically the signature type — `auth`/`sign`/`stamp`/`ping`/`attest`) gates which keys are considered via their `use=` option.
    #        Additional fields (e.g., `webAuthnOrigin`) are threaded through to crypto verifiers.
    # @param signed_data [Hash] The signature envelope's `signedMetadata`. Threaded to crypto verifiers but not consumed here. Defaults to `{}`.
    # @param unsigned_data [Hash] The signature envelope's `unsignedMetadata`. Threaded to crypto verifiers (e.g., WebAuthn reads `sig[idx]` from it). Defaults to `{}`.
    # @return [Hash, false]
    #         a `{valid: true, keys: Array, name: String, tag: String, expires: (Integer, nil)}` Hash when signatures have matched a keys group, false otherwise.
    def verify(message, signatures, context, signed_data = {}, unsigned_data = {})
      mode = context[:mode]

      # Helpers.log(@config, :debug, 'Triauth.IdentityKeys.verify', { message: message, signatures: signatures, context: context, signedData: signed_data, unsignedData: unsigned_data })

      # Make sure we do not have too many signatures to verify
      max_keys_per_signature = Protocol::LIMITS[:maxKeysPerSignature]
      if signatures.length > max_keys_per_signature
        Helpers.log(@config, :debug, "Too many signatures to verify - got #{signatures.length} with a limit of #{max_keys_per_signature}")
        return false
      end

      if signatures.any? { |s| !Helpers.is_base64url_string(s) }
        Helpers.log(@config, :debug, 'Non base64-url encoded signature detected')
        return false
      end

      # Attempt to verify each of keyGroups/devices, stop at and return the first matching/verified one
      Helpers.ordered_entries(@key_groups).each do |name, key_group| # `Object.entries(this.keyGroups)`: the JS object key order
        # Only take into account key groups that are considered valid, and have not expired.
        # Allow a grace window (the client clock drift allowance doubles as a generous upper bound for
        # in-call processing time) in expiry calculation, so that DNS key records with TTL=0 may still validate.
        if key_group[:valid] != true ||
           (!key_group[:expires].nil? && key_group[:expires] + @config[:maximalAllowedClientClockDrift] < Helpers.date_now)
          next
        end

        # Prepare a working copy of keys, and add the verified property
        # (a valid group has every slot populated - `add` marks it valid only then - so no nil slot is mapped)
        keys = key_group[:keys].map { |key| { value: key[:value], options: key[:options], verified: false, skipped: false } }

        # Go through each key and each signature looking for a match
        # This by its own has O(n^2) complexity, but should be fine, since the number of keys and signatures is limited.
        keys.each_with_index do |key, idx| # `Object.entries(keys)`: the index and the key
          # Only take into account keys with matching use mode (auth, sign, stamp).
          use = key[:options][:use]&.split(',', -1)
          if !mode.nil? && mode != '' && !use.nil? && !use.include?(mode) # `mode && use && ...`: string and array truthiness
            key[:skipped] = true
            next
          end

          # Get the correct crypto verifier for the given key type
          verifier_context = Helpers.object_assign({ idx: idx }, context)
          verifier = Triauth::Verifiers.get(key[:options][:type])&.from_publishable_key(key[:value], key[:options], verifier_context)
          if verifier.nil?
            Helpers.log(@config, :debug, 'Could not initialize verifier for key', { key: key })
            next
          end

          # Delegate signature verification to the crypto verifier
          signatures.each do |signature|
            key[:verified] ||= verifier.verify(message, signature, signed_data, unsigned_data)
          end

          # If the required key did not match any of the signatures, skip other keys from the keyGroup
          if key[:verified] != true
            break
          end
        end

        key_group_keys_match = keys.all? { |k| k[:verified] == true || k[:skipped] == true }
        verified_keys = keys.select { |k| k[:verified] == true }

        if keys.length > 0 && verified_keys.length > 0 && key_group_keys_match
          Helpers.log(@config, :debug, "Successful verification for deviceName #{name}", { deviceName: name.to_s, keys: keys })
          return {
            valid: true,
            keys: keys,
            name: name.to_s,
            tag: key_group[:tag],
            expires: key_group[:expires]
          }
        else
          Helpers.log(@config, :debug, "Failed verification for deviceName #{name}", { deviceName: name.to_s, keys: keys })
        end
      end

      return false
    end
  end
end
