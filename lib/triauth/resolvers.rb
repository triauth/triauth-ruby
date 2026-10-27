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


module Triauth
  # The namespace for DNS resolvers.
  module Resolvers
  end
end

require_relative 'resolvers/base'
require_relative 'resolvers/dns_json'
require_relative 'resolvers/multi_resolver'
require_relative 'resolvers/caching_resolver'
require_relative 'resolvers/cloudflare'
require_relative 'resolvers/google'
require_relative 'resolvers/system_dns'
require_relative 'resolvers/dns_sb'
