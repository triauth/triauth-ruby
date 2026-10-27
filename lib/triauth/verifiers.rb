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


require_relative 'verifiers/registry'
require_relative 'verifiers/base'
# Importing the concrete verifier modules for their side effects: each one calls
# `register(...)` at module-load time so that `Triauth::Verifiers.get(...)` works
# out of the box for 'es256', 'ed25519', 'webauthn-es256', and 'webauthn-ed25519'.
require_relative 'verifiers/ecdsa'
require_relative 'verifiers/ed25519'
require_relative 'verifiers/web_authn'

module Triauth
  # A collection holding information about registered digital signature verifiers.
  #
  # Each public key stored in the identity records in the DNS may be associated with a type of verifier that is to be used with it.
  module Verifiers
    # the JS re-exports (`register`, `get`, `list`, `Base`, `Ecdsa`, `Ed25519`, `WebAuthn`, `WebAuthnEs256`, `WebAuthnEd25519`)
    # have no counterpart: the module functions and the classes live on `Triauth::Verifiers` once their files are required
  end
end
