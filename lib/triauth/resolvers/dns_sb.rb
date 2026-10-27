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


require_relative 'dns_json'

module Triauth
  module Resolvers
    # A DNS resolver that uses the DNS.SB DoH JSON API endpoint
    #
    # @see https://dns.sb/doh/ Documentation
    # @see https://dns.sb/privacy/ Privacy Policy
    # @see https://dns.sb/tos/ Terms Of Service
    class DnsSb < DnsJson
      # @param options [Hash] Resolver options, as documented on {Triauth::Resolvers::DnsJson}.
      #   `normalizeTxtRecords` and `decodeTxtRecords` are always set to true
      #   for this endpoint, overriding whatever the caller passes. Defaults to `{}`.
      def initialize(options = {})
        options[:normalizeTxtRecords] = true # resolver returns TXT records in presentation form: each character-string double-quoted, e.g. "part1" "part2"
        options[:decodeTxtRecords] = true # resolver escapes non-printable ASCII characters into \\[decimal] form (RFC 1035 presentation format) instead of utf-8 encoding them
        super('https://doh.dns.sb/dns-query', options)
      end
    end
  end
end
