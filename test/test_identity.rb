# frozen_string_literal: true

require_relative 'setup'
require_relative 'stubs/dns_resolver'
# The demo zone, served from the fixture: the whois tests resolve through it, as the triauth-js run does through test_unit.js
require_relative 'stubs/zone_resolver'
require 'json'

# The identifiers fixture is read with String keys: the keys of `invalidIdentifiers` are identifier values, not property names.
# (guarded like the zone stub, so that test.rb and a standalone run load it once; shared with test_validation.rb)
IDENTIFIERS_FIXTURE = JSON.parse(File.read(File.expand_path('fixtures/identifiers.json', __dir__))) unless defined?(IDENTIFIERS_FIXTURE)

# The `captureLogger` object literal of triauth-js: `debug` records its first argument, the other levels are no-ops,
# and `spawn` returns the logger itself. Instantiated per test, as the literal is.
class CaptureLogger
  attr_reader :debug_messages

  def initialize
    @debug_messages = []
  end

  def debug(*args)
    @debug_messages.push(args[0])
  end

  def info(*); end
  def warn(*); end
  def error(*); end

  def spawn(_cid = nil)
    self
  end
end

describe 'Identity API' do
  describe 'Triauth.Identity.resolve (private mode)' do
    # The lookup code is a construction-time property of the Identity: it selects the identity
    # domain the records are read from, and the commit record makes those records exist only through the
    # commitment over the derivation actually performed.
    lookup_code = 'K7QJ3FB9M2WZX0C4'
    identity_domain = '_4GIBDU53B3._at.private.triauthdemo.org'
    commitment = '3Q7YSpb3MLMRaQ20VZBUfoySyM4vQrHMfIIuAxER3_s'

    private_resolver = lambda do |records|
      DnsResolverStub.new(
        {
          'private.triauthdemo.org': { TXT: ['triauth auth.private.triauthdemo.org mode=private'] },
          identity_domain.to_sym => { TXT: records }
        }
      )
    end

    records = ['name John Doe', "commit #{commitment}"]

    it 'resolves through the lookup code, and reports the derived identity domain' do
      identity = Triauth::Identity.new('john@private.triauthdemo.org', { lookupCode: lookup_code }, { resolver: private_resolver.call(records) })

      assert_equal true, identity.resolve
      assert_equal identity_domain, identity.identity_domain.domain_name
      assert_equal 'John Doe', identity.public_profile[:name]
    end

    it 'never resolves without a lookup code - no identity domain can be derived' do
      identity = Triauth::Identity.new('john@private.triauthdemo.org', {}, { resolver: private_resolver.call(records) })

      assert_equal false, identity.resolve
      assert_nil identity.identity_domain.domain_name
    end

    it 'never resolves when the commit record does not bind the derivation performed' do
      [
        [],                                                       # commitment absent
        ["commit #{'A' * 43}"],                                   # commitment mismatched
        ["commit #{commitment} evil=1"],                          # unknown critical option - malformed record
        ["commit #{commitment}", "commit #{'A' * 43}"]            # doubled - the label-merge tripwire
      ].each do |commit_records|
        identity = Triauth::Identity.new('john@private.triauthdemo.org', { lookupCode: lookup_code }, { resolver: private_resolver.call(['name John Doe', *commit_records]) })

        assert_equal false, identity.resolve, JSON.generate(commit_records)
      end
    end
  end

  describe 'Triauth.whois' do
    it 'returns correct identity details for valid identifiers' do
      whois_result = Triauth.whois({ identifier: 'john@triauthdemo.org' })
      assert_equal 1, whois_result[:status]

      public_profile = whois_result[:publicProfile]
      return assert_equal('John Doe', public_profile[:name])
    end

    it 'works with utf-8 encoded identity details' do
      whois_result = Triauth.whois({ identifier: 'frederic@triauthdemo.org' })
      return assert_equal('Frédéric Łukasiewicz', whois_result[:publicProfile][:name])
    end

    it 'returns {status:0} for missing identifiers under domains configured for triauth' do
      identifiers = ['missing-identifier@triauthdemo.org']
      identifiers.each do |identifier|
        whois_res = Triauth.whois({ identifier: identifier })
        assert_equal 0, whois_res[:status]
      end
    end

    it 'returns {error} for invalid identifiers' do
      invalid_identifiers = IDENTIFIERS_FIXTURE['invalidIdentifiers'] # `emptyIdentifiers` is destructured and unused in triauth-js
      results = []
      invalid_identifiers.each_key do |invalid_identifier| # `for...in`; the `errorMsg` read of triauth-js is unused there (`Lint/UselessAssignment` here)
        whois_res = Triauth.whois({ identifier: invalid_identifier })
        results.push(assert(whois_res[:error]))
      end
      return results
    end

    it 'returns {error} upon resolver failure' do
      identifiers = ['a@dnssec-failed.org']
      identifiers.each do |identifier|
        whois_res = Triauth.whois({ identifier: identifier })
        assert_equal 'dns_unavailable', whois_res[:error][:code]
      end
    end

    it 'returns {status:-1} if domain does not exist or is not configured for triauth' do
      identifiers = ['john@example.com', 'john@e.com']
      identifiers.each do |identifier|
        whois_res = Triauth.whois({ identifier: identifier })
        assert_equal(-1, whois_res[:status])
      end
    end

    it 'status-1 result includes identityDomain, authenticationEndpoint, and well-formed devices array' do
      whois_res = Triauth.whois({ identifier: 'john@triauthdemo.org' })
      assert_equal 1, whois_res[:status]

      assert whois_res[:identityDomain].is_a?(String) && whois_res[:identityDomain].length > 0

      assert whois_res[:authenticationEndpoint].is_a?(Hash)
      assert whois_res[:authenticationEndpoint][:url].is_a?(String) && whois_res[:authenticationEndpoint][:url].length > 0
      assert whois_res[:authenticationEndpoint][:options].is_a?(Hash)
      assert whois_res[:authenticationEndpoint][:secure] == true || whois_res[:authenticationEndpoint][:secure] == false # `typeof === 'boolean'`

      assert whois_res[:secure] == true || whois_res[:secure] == false, 'the resolution-level DNSSEC status is a top-level flag'

      assert whois_res[:devices].is_a?(Array) && whois_res[:devices].length > 0
      whois_res[:devices].each do |device|
        assert device[:deviceName].is_a?(String) && device[:deviceName].length > 0
        assert device[:deviceTag].is_a?(String) && device[:deviceTag].length > 0
        assert device[:keys].is_a?(Array) && device[:keys].length > 0
        assert device[:keys][0][:value].is_a?(String)
        assert device[:keys][0][:options].is_a?(Hash)
      end
    end

    it 'status-0 result includes authenticationEndpoint and identityDomain' do
      whois_res = Triauth.whois({ identifier: 'missing-identifier@triauthdemo.org' })
      assert_equal 0, whois_res[:status]

      assert whois_res[:identityDomain].is_a?(String) && whois_res[:identityDomain].length > 0
      assert whois_res[:authenticationEndpoint].is_a?(Hash)
      assert whois_res[:authenticationEndpoint][:url].is_a?(String) && whois_res[:authenticationEndpoint][:url].length > 0
      assert whois_res[:authenticationEndpoint][:options].is_a?(Hash)
      assert whois_res[:authenticationEndpoint][:secure] == true || whois_res[:authenticationEndpoint][:secure] == false
    end

    it 'ignores DNS identity records with unrecognized keywords' do
      # Identity records may legitimately carry keywords the library doesn't know about
      # (forward compatibility). They should be silently dropped during resolution
      # and not contaminate publicProfile or device keys.
      dns_records = {
        'example.org': {
          TXT: [{ value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true }]
        },
        'unknown._at.example.org': {
          TXT: [
            { value: 'name Forward Compat',                                                                            ttl: 1800, dnssec: true },
            { value: 'initials FC',                                                                                    ttl: 1800, dnssec: true },
            { value: 'tagline Builder of things',                                                                      ttl: 1800, dnssec: true },
            { value: 'x-acme-team Platform',                                                                           ttl: 1800, dnssec: true },
            { value: "x-acme-long #{'a' * 300}",                                                                       ttl: 1800, dnssec: true },
            { value: 'future-feature some-future-value',                                                               ttl: 1800, dnssec: true },
            { value: 'foo bar',                                                                                        ttl: 1800, dnssec: true },
            { value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true }
          ]
        }
      }
      resolver = DnsResolverStub.new(dns_records)

      # Capture debug output to assert the "Ignoring unrecognized identity record"
      # line fires for the unknown keywords.
      capture_logger = CaptureLogger.new

      whois_res = Triauth.whois({ identifier: 'unknown@example.org' }, { resolver: resolver, logger: capture_logger })

      assert_equal 1, whois_res[:status]
      assert_equal 'Forward Compat', whois_res[:publicProfile][:name]
      assert_equal 'FC', whois_res[:publicProfile][:initials]
      refute whois_res[:publicProfile].key?(:tagline), 'tagline is no longer a recognized publicProfile keyword (dropped like other unrecognized keywords)'
      # `x-` prefixed keywords are passed through verbatim...
      assert_equal 'Platform', whois_res[:publicProfile][:'x-acme-team']
      # ...but an over-length value (> publicProfileMaxValueBytesize) is rejected, not truncated.
      refute whois_res[:publicProfile].key?(:'x-acme-long'), 'over-length extension values must be rejected'
      refute whois_res[:publicProfile].key?(:'future-feature'), 'unknown keywords must not leak into publicProfile'
      refute whois_res[:publicProfile].key?(:foo)
      assert whois_res[:devices].is_a?(Array) && whois_res[:devices].length > 0
      assert capture_logger.debug_messages.include?('Ignoring unrecognized identity record'), 'expected the "Ignoring unrecognized identity record" debug line to fire'
    end

    it 'caps the number of distinct `x-` extensions but never drops reserved keywords' do
      # A domain could publish an unbounded number of `x-` extension records; only the first
      # LIMITS.publicProfileMaxExtensions distinct ones are kept. Reserved keywords live in a
      # separate, bounded allowlist and must survive regardless of record order or extension flood.
      over_limit = Triauth::LIMITS[:publicProfileMaxExtensions] + 5
      extension_records = (0...over_limit).map do |i|
        { value: "x-f#{i} v#{i}", ttl: 1800, dnssec: true }
      end

      dns_records = {
        'example.org': { TXT: [{ value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true }] },
        'flood._at.example.org': {
          TXT: [
            *extension_records,
            # reserved keyword declared AFTER the extension flood - must still be kept
            { value: 'name Flooded User', ttl: 1800, dnssec: true },
            { value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true }
          ]
        }
      }
      resolver = DnsResolverStub.new(dns_records)

      capture_logger = CaptureLogger.new

      whois_res = Triauth.whois({ identifier: 'flood@example.org' }, { resolver: resolver, logger: capture_logger })

      extension_keys = whois_res[:publicProfile].keys.select { |k| k.to_s.start_with?('x-') }
      assert_equal Triauth::LIMITS[:publicProfileMaxExtensions], extension_keys.length, 'extensions must be capped'
      assert_equal 'Flooded User', whois_res[:publicProfile][:name], 'reserved keyword must survive the extension flood'
      assert capture_logger.debug_messages.include?('Ignoring publicProfile extension over the limit'), 'expected the over-limit debug line to fire'
    end

    it 'drops a publicProfile keyword entirely when it appears more than once' do
      # Doubled keywords are ambiguous, so both the reserved and the `x-` variants are dropped
      # entirely rather than guessing first- or last-wins.
      dns_records = {
        'example.org': { TXT: [{ value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true }] },
        'dup._at.example.org': {
          TXT: [
            { value: 'name First',     ttl: 1800, dnssec: true },
            { value: 'name Second',    ttl: 1800, dnssec: true },
            { value: 'initials OK',    ttl: 1800, dnssec: true },
            { value: 'x-dup one',      ttl: 1800, dnssec: true },
            { value: 'x-dup two',      ttl: 1800, dnssec: true },
            { value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true }
          ]
        }
      }
      resolver = DnsResolverStub.new(dns_records)

      capture_logger = CaptureLogger.new

      whois_res = Triauth.whois({ identifier: 'dup@example.org' }, { resolver: resolver, logger: capture_logger })

      refute whois_res[:publicProfile].key?(:name), 'a doubled reserved keyword must be dropped entirely'
      refute whois_res[:publicProfile].key?(:'x-dup'), 'a doubled extension keyword must be dropped entirely'
      assert_equal 'OK', whois_res[:publicProfile][:initials], 'non-doubled keywords are unaffected'
      assert capture_logger.debug_messages.include?('Ignoring doubled publicProfile entry'), 'expected the doubled-entry debug line to fire'
    end

    it 'reports resolution-level secure:false when the triauth configuration record is not DNSSEC protected' do
      key_record = 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8'

      [[true, true], [false, false]].each do |endpoint_dnssec, expected_secure|
        resolver = DnsResolverStub.new(
          {
            'example.org': {
              TXT: [{ value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: endpoint_dnssec }]
            },
            'john._at.example.org': {
              TXT: [{ value: key_record, ttl: 1800, dnssec: true }]
            }
          }
        )

        whois_res = Triauth.whois({ identifier: 'john@example.org' }, { resolver: resolver })

        assert_equal 1, whois_res[:status]
        assert_equal 1, whois_res[:devices].length
        assert_equal expected_secure, whois_res[:secure], "endpoint dnssec:#{endpoint_dnssec} must yield secure:#{expected_secure}"
      end
    end

    describe 'include records' do
      key_record = { value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true }

      # Resolves team@example.org against a zone with the given endpoint record and
      # extra identity records, and returns the include statements it ends up with.
      # (a method, not a lambda: a lambda in a describe body cannot assert - its `self` is the spec class)
      define_method(:resolved_includes) do |endpoint_record, identity_records|
        resolver = DnsResolverStub.new(
          {
            'example.org': { TXT: [{ value: endpoint_record, ttl: 1800, dnssec: true }] },
            'team._at.example.org': { TXT: [key_record, *identity_records] }
          }
        )
        identity = Triauth::Identity.new('team@example.org', {}, { resolver: resolver })
        assert_equal true, identity.resolve
        identity.includes.includes
      end

      it "gates include records through the endpoint record's include option (default: any)" do
        records = [
          { value: 'include mate@example.org use=sign scope=any', ttl: 1800, dnssec: true },
          { value: 'include ext@other.example scope=any',         ttl: 1800, dnssec: true }
        ]

        admitted = resolved_includes('triauth local-auth.example.org mode=public', records)
        assert_equal ['ext@other.example', 'mate@example.org'], admitted.map { |i| i[:ref] }.sort, 'the default policy admits local and foreign refs alike'
        assert_equal 'sign', admitted.find { |i| i[:ref] == 'mate@example.org' }[:options][:use], 'record options must reach the include statement'

        assert_equal 0, resolved_includes('triauth local-auth.example.org include=none mode=public', records).length
        assert_equal(
          ['mate@example.org'],
          resolved_includes('triauth local-auth.example.org include=local mode=public', records).map { |i| i[:ref] },
          'include=local admits (only) refs on the identity domain'
        )
        assert_equal(
          ['ext@other.example'],
          resolved_includes('triauth local-auth.example.org include=other.example mode=public', records).map { |i| i[:ref] },
          'an allowlisted domain admits (only) its refs'
        )
      end

      it 'carries per-record freshness: expires from the TTL (absent TTL: undefined, never NaN)' do
        includes = resolved_includes(
          'triauth local-auth.example.org include=any mode=public',
          [
            { value: 'include mate@example.org scope=any', ttl: 1800, dnssec: true },
            { value: 'include peer@other.example scope=any',          dnssec: false }
          ]
        )

        mate = includes.find { |i| i[:ref] == 'mate@example.org' }
        peer = includes.find { |i| i[:ref] == 'peer@other.example' }
        assert mate[:expires].is_a?(Integer) && mate[:expires] > Triauth::Helpers.date_now, 'a TTL yields a finite future expires'
        assert_nil peer[:expires], 'a record without a TTL yields no expires' # `strictEqual(x, undefined)`: nil is the JS `undefined` of an optional output field
      end
    end

    describe 'groups records' do
      key_record = { value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true }
      rec = ->(value) { { value: value, ttl: 1800, dnssec: true } }

      # Resolves team@example.org against a zone carrying the given extra identity records and
      # returns the whois result together with the captured debug lines.
      # (a method, not a lambda: a lambda in a describe body cannot assert - its `self` is the spec class)
      define_method(:resolved_whois) do |identity_records|
        resolver = DnsResolverStub.new(
          {
            'example.org': { TXT: [{ value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true }] },
            'team._at.example.org': { TXT: [key_record, *identity_records] }
          }
        )
        capture_logger = CaptureLogger.new
        whois_res = Triauth.whois({ identifier: 'team@example.org' }, { resolver: resolver, logger: capture_logger })
        assert_equal 1, whois_res[:status]
        { whoisRes: whois_res, debugMessages: capture_logger.debug_messages }
      end

      it 'surfaces groups as fully-qualified names - union across records, deduplicated, sorted ascending' do
        whois_res = resolved_whois(
          [
            rec.call('groups zeta,admins'),
            rec.call('groups admins,project3')
          ]
        )[:whoisRes]
        assert_equal ['admins@example.org', 'project3@example.org', 'zeta@example.org'], whois_res[:groups]
      end

      it 'yields the same list regardless of DNS answer order' do
        a = resolved_whois([rec.call('groups zeta'), rec.call('groups admins')])
        b = resolved_whois([rec.call('groups admins'), rec.call('groups zeta')])
        assert_equal b[:whoisRes][:groups], a[:whoisRes][:groups]
      end

      it 'lowercases the record value before validation - names surface normalized' do
        whois_res = resolved_whois([rec.call('groups Admins,PROJECT3')])[:whoisRes]
        assert_equal ['admins@example.org', 'project3@example.org'], whois_res[:groups]
      end

      it 'an empty element (trailing comma) voids the whole record - siblings stay effective' do
        whois_res, debug_messages = resolved_whois(
          [
            rec.call('groups admins,'),
            rec.call('groups project3')
          ]
        ).values_at(:whoisRes, :debugMessages)
        assert_equal ['project3@example.org'], whois_res[:groups]
        assert debug_messages.include?('Ignoring groups record with a malformed group name'), 'expected the malformed-name debug line to fire'
      end

      it 'one grammar-invalid element voids the whole record - never repaired to the valid subset' do
        whois_res = resolved_whois([rec.call('groups good,-bad,alsogood')])[:whoisRes]
        assert_equal [], whois_res[:groups]
      end

      it 'rejects names outside the device-name grammar (dots, underscores, hyphen placement, spaces)' do
        ['groups a.b', 'groups under_score', 'groups -lead', 'groups trail-', 'groups dou--ble', 'groups two words', 'groups ,'].each do |value|
          whois_res = resolved_whois([rec.call(value)])[:whoisRes]
          assert_equal [], whois_res[:groups], "#{JSON.generate(value)} must void the record"
        end
      end

      it 'enforces the 20-byte name cap - a boundary-length name passes, one byte over voids the record' do
        ok = 'a' * 20
        over = 'a' * 21
        assert_equal ["#{ok}@example.org"], resolved_whois([rec.call("groups #{ok}")])[:whoisRes][:groups]
        assert_equal [], resolved_whois([rec.call("groups #{over}")])[:whoisRes][:groups]
      end

      it 'a groups record carrying any critical option is ignored as a whole; x- options are inert' do
        whois_res, debug_messages = resolved_whois(
          [
            rec.call('groups admins use=auth'),
            rec.call('groups project3 x-note=hi')
          ]
        ).values_at(:whoisRes, :debugMessages)
        assert_equal ['project3@example.org'], whois_res[:groups]
        assert debug_messages.include?('Ignoring groups record due to unrecognized options'), 'expected the unrecognized-options debug line to fire'
      end

      it 'caps distinct names at LIMITS.maxGroups in processing order; duplicates never consume the cap' do
        first = (0...(Triauth::LIMITS[:maxGroups] - 5)).map { |i| "g#{i.to_s.rjust(3, '0')}" }
        second = ['g000', *(0...10).map { |i| "h#{i.to_s.rjust(2, '0')}" }]
        whois_res, debug_messages = resolved_whois(
          [
            rec.call("groups #{first.join(',')}"),
            rec.call("groups #{second.join(',')}")
          ]
        ).values_at(:whoisRes, :debugMessages)
        assert_equal Triauth::LIMITS[:maxGroups], whois_res[:groups].length
        assert whois_res[:groups].include?('h04@example.org'), 'the final distinct name under the cap must be kept (the duplicate before it consumed no budget)'
        refute whois_res[:groups].include?('h05@example.org'), 'names beyond the cap must be dropped'
        assert debug_messages.include?('Ignoring groups and further group records over the limit'), 'expected the one-time over-limit summary to fire'
      end

      it 'a groups record is recognized - it does not fire the unrecognized-identity-record debug line' do
        debug_messages = resolved_whois([rec.call('groups admins')])[:debugMessages]
        refute debug_messages.include?('Ignoring unrecognized identity record')
      end

      it 'an identity without groups records yields groups: []' do
        whois_res = resolved_whois([])[:whoisRes]
        assert_equal [], whois_res[:groups]
      end

      it 'coexists with keys, includes, and profile records without cross-interference' do
        whois_res = resolved_whois(
          [
            rec.call('name Team Account'),
            rec.call('include mate@example.org use=sign scope=any'),
            rec.call('groups admins')
          ]
        )[:whoisRes]
        assert_equal ['admins@example.org'], whois_res[:groups]
        assert_equal 'Team Account', whois_res[:publicProfile][:name]
        assert_equal 1, whois_res[:includes].length
        assert_equal 1, whois_res[:devices].length
      end

      it 'SECURITY: any non-DNSSEC identity record degrades the resolution-level secure - DNSSEC is full-in or full-out' do
        # The groups, profile, and even unrecognized-key variants all degrade the resolution,
        # and whois surfaces the same resolution-level flag the verification flows report.
        ['groups admins', 'name Team Account', 'future-key whatever'].each do |insecure_record|
          resolver = DnsResolverStub.new(
            {
              'example.org': { TXT: [{ value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true }] },
              'team._at.example.org': { TXT: [key_record, { value: insecure_record, ttl: 1800, dnssec: false }] }
            }
          )
          whois_res = Triauth.whois({ identifier: 'team@example.org' }, { resolver: resolver })
          check_res = Triauth.check({ identifier: 'team@example.org', deviceTag: whois_res[:devices][0][:deviceTag] }, { resolver: resolver })
          assert_equal true, check_res[:valid]
          assert_equal false, check_res[:secure], "a non-DNSSEC \"#{insecure_record}\" record must degrade the resolution-level secure"
          assert_equal false, whois_res[:secure], 'whois surfaces the same resolution-level status'
        end

        # The all-validated contrast: the same zone with every record DNSSEC-validated is secure
        resolver = DnsResolverStub.new(
          {
            'example.org': { TXT: [{ value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true }] },
            'team._at.example.org': { TXT: [key_record, rec.call('groups admins')] }
          }
        )
        whois_res = Triauth.whois({ identifier: 'team@example.org' }, { resolver: resolver })
        check_res = Triauth.check({ identifier: 'team@example.org', deviceTag: whois_res[:devices][0][:deviceTag] }, { resolver: resolver })
        assert_equal true, whois_res[:secure]
        assert_equal true, check_res[:secure]
        assert_equal ['admins@example.org'], check_res[:groups], "check carries the identity's current groups"
      end
    end
  end
end
