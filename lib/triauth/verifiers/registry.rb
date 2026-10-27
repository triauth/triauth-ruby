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


require_relative '../helpers'

module Triauth
  # Holds information about registered digital signature verifiers.
  # Each public key stored in the identity records in the DNS may be associated with a type of verifier that is to be used with it (e.g., `type=es256`).
  module Verifiers
    # the registry keys are wire values: the type String as published in the key record (`'es256'`), never a Symbol - like the LRU cache keys
    @verifiers = {}

    # Registers a verifier class that should be used for keys of the given type.
    #
    # @param type [String] the type of key, e.g., 'es256'
    # @param verifier_class [Class] a class descending from `Triauth::Verifiers::Base` that should handle the keys of given type
    def self.register(type, verifier_class)
      @verifiers[type] = verifier_class
    end

    # Returns a verifier registered for the given key type.
    #
    # @param type [String] the type of the key for which verifier is being looked for
    # @return [Class, nil] A class that descends from `Triauth::Verifiers::Base` (with a `from_publishable_key` factory) that is responsible for handling given keys, or nil if not found.
    def self.get(type)
      return @verifiers[type]
    end

    # Returns a list of registered verifier's types
    #
    # @return [Array<String>]
    def self.list
      return Helpers.ordered_entries(@verifiers).map(&:first) # `Object.keys`: an integer-like type lists first, in numeric order
    end
  end
end
