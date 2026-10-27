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


require_relative '../config'
require_relative '../helpers'
require_relative '../validator'

module Triauth
  module Api
    # Methods related to validation of various objects related to the triauth protocol
    module Validation
      # The validate method can be used to perform a basic format validation on the given objects.
      # It is fast, synchronous, and does not perform any DNS requests.
      #
      # Currently, it supports validation of personal identifiers (`identifier`), device names (`deviceName`),
      # group names (`groupName`, the bare name as published in a `groups` record, e.g., `admins`),
      # lookup codes (`lookupCode`, the 16-character code of an identity under a `mode=private` domain),
      # and device tags (`deviceTag`, as reported in results and passed to `Triauth.check`).
      # At least one of the supported objects must be provided, and unrecognized (e.g., misspelled)
      # keys are rejected, so that nothing silently passes as valid without being validated.
      #
      # Synopsis:
      #
      # ```ruby
      # validation_result = Triauth.validate({ identifier?, deviceName?, groupName?, lookupCode?, deviceTag? })
      # # returns {valid: true, errors: []} if all the objects passed validation
      # # returns {valid: false, errors: [{code: ..., reason: ..., message: ...}, ...]} if at least one the objects failed validation
      # # returns {valid: false, errors: [{code: 'invalid_arguments', ...}]} when objects is empty or not a Hash, or contains an unrecognized key
      # # returns {valid: false, errors: [{code: 'invalid_config', ...}]} when config contains an unrecognized key
      #
      # ```
      #
      # Example:
      #
      # ```ruby
      # Triauth.validate({ identifier: 'john@triauthdemo.org' })
      # # {valid: true, errors: []}
      #
      # Triauth.validate({ identifier: 'john' })
      # # {valid: false, errors: [{code: 'invalid_identifier', reason: 'invalid_format', message: 'Identifier must include one @ sign'}]}
      #
      # Triauth.validate({ groupName: 'admins@example.com' })
      # # {valid: false, errors: [{code: 'invalid_group_name', reason: 'invalid_characters', message: 'Group name must include only letters, numbers, and hyphens'}]}
      #
      # Triauth.validate({ lookupCode: 'k7qj3fb9m2wzx0c4' })
      # # {valid: false, errors: [{code: 'invalid_lookup_code', reason: 'invalid', message: 'Invalid lookup code'}]}
      #
      # Triauth.validate({ deviceTag: '3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ~K7QJ3FB9M2WZX0C4' })
      # # {valid: true, errors: []}
      # ```
      #
      # > [!NOTE]
      # > `{valid: true}` confirms the *format* only - it is not input sanitization.
      # > Callers must still encode or escape the value for whatever sink it flows into (SQL, shell, file paths, HTML, log lines).
      #
      # @param objects [Hash] one or more objects to validate. Defaults to nil (a missing argument is rejected with `invalid_arguments`).
      # @option objects [String] :identifier an identifier to validate
      # @option objects [String] :deviceName a deviceName to validate
      # @option objects [String] :groupName a bare group name to validate (e.g., `admins`)
      # @option objects [String] :lookupCode a lookup code to validate (e.g., `K7QJ3FB9M2WZX0C4`)
      # @option objects [String] :deviceTag a device tag to validate, plain or composite (e.g., `3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ`)
      # @param config [Hash] optional overrides for the global Triauth.config settings; unrecognized keys are rejected (`invalid_config`). Defaults to `{}`.
      #
      # @return [Hash] `{valid: Boolean, errors: Array<{code: String, reason?: String, message: String}>}`
      #                A Hash with valid property containing the validation result,
      #                and the errors property containing an array of errors (if any),
      #                in the `{code, reason?, message}` format.
      def self.validate(objects = nil, config = {})
        # `objects` must be a plain object with at least one supported entry,
        # so that e.g. validate(null) or validate({}) cannot pass as valid.
        # (`!objects || typeof objects !== 'object' || Array.isArray(objects)` is "not a Hash": nil, false, strings, numbers, true and Arrays all take this branch, as in JS)
        if !objects.is_a?(Hash) || objects.empty?
          return {
            valid: false,
            errors: [{ code: 'invalid_arguments', message: 'Invalid or missing function arguments' }]
          }
        end

        # Ensure only recognized objects with defined values are present to help avoid misspellings.
        if !Helpers.has_only_known_properties(objects, %i[identifier deviceName groupName lookupCode deviceTag])
          return {
            valid: false,
            errors: [{ code: 'invalid_arguments', message: 'Unrecognized function argument' }]
          }
        end

        # Reject config overrides carrying unknown keys
        if !Helpers.has_only_known_properties(Helpers.merge_config(config), Triauth::KNOWN_CONFIG_KEYS)
          return {
            valid: false,
            errors: [{ code: 'invalid_config', message: 'Unrecognized configuration key' }]
          }
        end

        retval = {
          valid: true,
          errors: []
        }

        keys = objects.keys

        if keys.include?(:identifier)
          vr = Validator.validate_identifier(objects[:identifier])
          if !vr[:valid]
            retval[:valid] = false
            retval[:errors] = retval[:errors] + vr[:errors] # `concat` returns a new array (never `Array#concat`, which mutates)
          end
        end

        if keys.include?(:deviceName)
          vr = Validator.validate_device_name(objects[:deviceName])
          if !vr[:valid]
            retval[:valid] = false
            retval[:errors] = retval[:errors] + vr[:errors]
          end
        end

        if keys.include?(:groupName)
          vr = Validator.validate_group_name(objects[:groupName])
          if !vr[:valid]
            retval[:valid] = false
            retval[:errors] = retval[:errors] + vr[:errors]
          end
        end

        if keys.include?(:lookupCode)
          vr = Validator.validate_lookup_code(objects[:lookupCode])
          if !vr[:valid]
            retval[:valid] = false
            retval[:errors] = retval[:errors] + vr[:errors]
          end
        end

        if keys.include?(:deviceTag)
          vr = Validator.validate_device_tag(objects[:deviceTag])
          if !vr[:valid]
            retval[:valid] = false
            retval[:errors] = retval[:errors] + vr[:errors]
          end
        end

        return retval
      end
    end
  end
end
