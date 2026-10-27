# frozen_string_literal: true

require 'json'
require_relative 'dns_resolver'

# The stub zone and the resolver over it are constants of this module (the JS exports `zoneResolver` and `dnsRecords`);
# the guards keep a second load of this file harmless.
module TestStubs
  DNS_RECORDS = JSON.parse(File.read(File.expand_path('../fixtures/dns_records.json', __dir__)), symbolize_names: true) unless defined?(DNS_RECORDS)

  # The suite's DNS served from the fixture
  ZONE_RESOLVER = DnsResolverStub.new(DNS_RECORDS) unless defined?(ZONE_RESOLVER)
end

Triauth.config[:resolver] = TestStubs::ZONE_RESOLVER
