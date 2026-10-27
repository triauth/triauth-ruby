# frozen_string_literal: true

require_relative '../setup'
require 'json'

# Counts what reaches the network; the cache must answer the second query by itself.
# (A class cannot be defined inside a method body, so it lives here instead of inside the CachingResolver describe.)
class Counting < Triauth::Resolvers::Base
  attr_reader :inner, :calls

  def initialize(inner)
    super()
    @inner = inner
    @calls = 0
  end

  def resolve(*)
    @calls += 1
    return @inner.resolve(*)
  end
end

module TestInternals
  def self.resolvers_zone
    zone = JSON.parse(File.read(File.expand_path('../fixtures/dns_test_zone.json', __dir__)), symbolize_names: true)

    # The concrete resolvers against real answers

    # `ENTRIES`, `EXTERNAL` and `MATRIX` are locals here (a constant cannot be assigned inside a method body); the names
    # are the JS object keys, Strings as `Object.entries` yields them
    entries = zone[:names].merge(zone[:external]).transform_keys(&:to_s)
    external = zone[:external].keys.to_set(&:to_s)

    # Fresh instances per test: the Cloudflare/DnsSb constructors set their TXT flags on the options
    # object they receive, so no two resolvers may share one. Retry/timeout settings are the fleet's.
    doh_options = -> { { retries: 1, timeout: 4000 } }

    # The composition lib/triauth.rb installs by default. Under `rake test` Triauth.config[:resolver] is the
    # fixture zone, so the shipped fleet is rebuilt here to be exercised against real answers.
    make_default_composition = lambda do
      Triauth::Resolvers::MultiResolver.new([
                                              Triauth::Resolvers::Cloudflare.new(doh_options.call),
                                              Triauth::Resolvers::Google.new(doh_options.call),
                                              Triauth::Resolvers::SystemDns.new({ timeout: 4000 })
                                            ], { maxFailures: 1, timeout: 8500 })
    end

    # The 'NodeDns' label reads 'SystemDns' (the planned rename), so the generated test names read `SystemDns ...`
    # where triauth-js reads `NodeDns ...`.
    matrix = [
      { label: 'Cloudflare', kind: 'doh',   make: -> { Triauth::Resolvers::Cloudflare.new(doh_options.call) } },
      { label: 'Google',     kind: 'doh',   make: -> { Triauth::Resolvers::Google.new(doh_options.call) } },
      { label: 'DnsSb',      kind: 'doh',   make: -> { Triauth::Resolvers::DnsSb.new(doh_options.call) } },
      { label: 'SystemDns',  kind: 'node',  make: -> { Triauth::Resolvers::SystemDns.new({ timeout: 2000, tries: 2 }) }, nodeOnly: true },
      { label: 'MultiResolver (default composition)', kind: 'multi', make: make_default_composition }
    ]

    it_ = ->(r) { r[:nodeOnly] == true ? :it_node : :it } # the DSL method that defines the cell (called through `public_send`)
    query_name = ->(name, entry) { entry[:query].nil? ? name : entry[:query] }
    values = ->(records) { records.map { |r| r[:value] }.sort }
    strip_dot = ->(v) { v.sub(/\.\z/, '') }
    plain = ->(options) { Triauth::Helpers.object_assign({}, options) }
    sorted_config = lambda do |config_entries| # (`entries` would shadow the outer local)
      config_entries
        .map { |e| { key: e[:key], value: e[:value], options: plain.call(e[:options]) } }
        .sort_by { |e| e[:key] + e[:value] } # `localeCompare`: both sides are sorted by the same comparator, so byte order serves
    end

    # One expectation per (resolver kind, entry): {mode:'values', values} | {mode:'min', min} |
    # {mode:'reject'} | {mode:'reject-or-resolve'}. Unless the fixture says otherwise, a name resolves
    # to its published TXT strings, and a name with no TXT resolves to nothing.
    expectation_for = lambda do |kind, entry, spec = (entry[:expect].nil? ? nil : entry[:expect][kind.to_sym])|
      return { mode: spec } if Triauth::Helpers.is_string(spec)
      return { mode: 'values', values: entries[spec[:valuesOf]][:records][:TXT] } if spec.is_a?(Hash) && !spec[:valuesOf].nil? && !spec[:valuesOf].empty?
      return { mode: 'values', values: spec[:values] } if spec.is_a?(Hash) && !spec[:values].nil?
      return { mode: 'min', min: spec[:minRecords] } if spec.is_a?(Hash) && !spec[:minRecords].nil? && spec[:minRecords] != 0

      return { mode: 'values', values: entry[:records].nil? || entry[:records][:TXT].nil? ? [] : entry[:records][:TXT] }
    end

    summary = lambda do |exp|
      {
        'values' => exp[:values].nil? || exp[:values].length == 0 ? 'an empty answer' : "the #{exp[:values].length} published value(s)",
        'min' => "at least #{exp[:min]} record(s)",
        'reject' => 'a rejection',
        'reject-or-resolve' => 'a rejection, or records the system resolver vouches for'
      }[exp[:mode]]
    end

    # Per-record shape by resolver kind: DoH answers carry a TTL within the published bound and the
    # response-level AD bit; SystemDns carries the TTL and no DNSSEC status (node:dns carries neither).
    # (`test` is the running test: a lambda defined here cannot assert on its own, mocha's `assert` is global)
    assert_shape = lambda do |test, kind, records, name, entry|
      ttl_max = external.include?(name) ? nil : zone[:defaults][:ttl]
      ttl_max = entry[:ttl] unless entry[:ttl].nil? # `entry.ttl ?? ...`
      dnssec = entry[:dnssec].nil? ? zone[:defaults][:dnssec] : entry[:dnssec]
      records.each do |record|
        if kind == 'node'
          # the system resolver's TTL is whatever the local recursive resolver reports (a NAT resolver here answers 168 for
          # a 60 s record), so only its type is pinned (triauth-js asserts `ttl` undefined under node)
          test.assert(Triauth::Helpers.is_integer(record[:ttl]) && record[:ttl] >= 0, "#{name}: SystemDns reports an Integer ttl, got #{record[:ttl].inspect}")
          test.assert_nil(record[:dnssec], "#{name}: SystemDns reports no DNSSEC status")
        else
          test.assert(Triauth::Helpers.is_integer(record[:ttl]) && record[:ttl] > 0 && (ttl_max.nil? || record[:ttl] <= ttl_max),
                      "#{name}: ttl #{record[:ttl]} must lie in (0, #{ttl_max.nil? ? '∞' : ttl_max}]")
          test.assert_equal(dnssec, record[:dnssec], "#{name}: dnssec must be #{dnssec} (\"#{record[:value]}\")")
        end
      end
    end

    # Settles a resolution into {records} | {error}, retrying a rejection once - one slow provider
    # must not fail a cell whose expectation is an answer.
    settle = lambda do |query|
      { records: query.call }
    rescue StandardError => first
      begin
        { records: query.call }
      rescue StandardError => error
        { error: error, first: first }
      end
    end

    # A system resolver that cannot deliver a large RRset in full is an environment limit: some relays
    # cap the answer at their buffer even over TCP, and some recursive services pass an upstream
    # truncation on as a complete answer. SystemDns then returns a strict subset of the published values,
    # and so does the default composition, whose intersection shrinks with its SystemDns member. Such a
    # cell fails with the cause and the remedy instead of a value diff. Each answer is judged on its own
    # values, because two concurrent SystemDns queries for one name can be served differently by the same
    # resolver. Only a non-empty strict subset of the published values qualifies.
    truncated_by = lambda do |entry, outcome|
      published = entry[:records].nil? || entry[:records][:TXT].nil? ? [] : entry[:records][:TXT] # `entry.records?.TXT ?? []`
      got = outcome.nil? || outcome[:records].nil? ? [] : outcome[:records] # `outcome?.records ?? []`
      subset = got.length > 0 && got.length < published.length && got.all? { |r| published.include?(r[:value]) }
      return entry[:large] == true && IS_NODE && subset ? "#{got.length} of #{published.length}" : nil
    end
    truncation_error = lambda do |name, short, through|
      RuntimeError.new(
        "the system resolver delivers #{short} records of #{name} through #{through}. The resolver path of this machine cuts large answers. " \
        'Point it at a full recursive resolver (README, Best Practices, "Make sure the system resolver delivers large answers in full"), ' \
        'or set TRIAUTH_SKIP_ZONE_TESTS=1 to leave the live zone tests out'
      )
    end

    # The cell: mocha context is `this` (function-style tests) so optional samples can go pending.
    # (`test` is the running test, as `assertCell.call(this, ...)` passes mocha's `this`; `skip` raises `Minitest::Skip`)
    assert_cell = lambda do |test, kind, outcome, name, entry, exp, value_of = ->(v) { v }|
      if exp[:mode] == 'reject'
        test.assert(outcome.key?(:error), "#{name}: expected a rejection, got #{JSON.generate(outcome[:records])}")
        return
      end

      if exp[:mode] == 'reject-or-resolve'
        assert_shape.call(test, kind, outcome[:records], name, entry) if !outcome[:records].nil?
        return
      end

      test.assert(outcome.key?(:records), "#{name}: expected records, got rejection #{outcome[:error]&.message}")
      records = outcome[:records]
      if entry[:optional] == true
        signed_after_all = kind != 'node' && records.any? { |r| r[:dnssec] != (entry[:dnssec].nil? ? zone[:defaults][:dnssec] : entry[:dnssec]) }
        if records.length == 0 || signed_after_all
          warn("[zone] optional sample #{name} #{records.length == 0 ? 'answers nothing' : 'no longer matches its DNSSEC expectation'} - pick another sample")
          test.skip("[zone] optional sample #{name} - pick another sample")
        end
      end
      if exp[:mode] == 'min'
        test.assert(records.length >= exp[:min], "#{name}: expected at least #{exp[:min]} record(s), got #{records.length}")
      else
        test.assert_equal(exp[:values].sort, records.map { |r| value_of.call(r[:value]) }.sort, "#{name}: value set")
      end
      assert_shape.call(test, kind, records, name, entry)
    end

    describe "DNS test zone (#{zone[:zone]}, published)" do
      # `this.timeout(20000)` and `this.slow(5000)` have no counterpart: minitest has no per-suite timeout

      # the port's offline lane (`TRIAUTH_OFFLINE`) skips the zone as `TRIAUTH_SKIP_ZONE_TESTS` does
      skip_zone_tests = ENV.fetch('TRIAUTH_SKIP_ZONE_TESTS', nil)
      offline = ENV.fetch('TRIAUTH_OFFLINE', nil)
      if (!skip_zone_tests.nil? && !skip_zone_tests.empty?) || (!offline.nil? && !offline.empty?)
        it 'skipped by TRIAUTH_SKIP_ZONE_TESTS - offline development' do
          skip
        end
        next # the JS `return`: leaves the describe body (a `return` would unwind through minitest's `describe`)
      end

      # Fail fast, once, with the reason: an unreachable, unpublished, stale or unsigned zone, or a
      # resolver path that cuts large answers, would otherwise surface as many individual failures.
      # (a mocha `before` runs once per describe where minitest's runs before every test: the preflight is memoized and
      # its outcome - `:done` or the error - is replayed to every test; `this.timeout(25000)` has no counterpart)
      preflight = nil
      zone_preflight = lambda do
        preflight ||= begin
          probe = lambda do |resolver_class|
            { records: resolver_class.new({ retries: 2, timeout: 4000 }).resolve(zone[:zone], 'TXT') }
          rescue StandardError => error
            { error: error }
          end
          apex = zone[:names][zone[:zone].to_sym][:records][:TXT]
          marker = apex.find { |v| v.start_with?('zone-version ') }
          cloudflare = probe.call(Triauth::Resolvers::Cloudflare)
          if !cloudflare[:error].nil?
            # `error?.message ?? error`: the rescued value is always an exception here
            raise "#{zone[:zone]} is unreachable through Cloudflare DoH (#{cloudflare[:error].message}) - the zone tests need network access"
          end

          if !cloudflare[:records].any? { |r| r[:value] == apex[0] }
            raise "#{zone[:zone]} publishes no \"#{apex[0]}\" record: the zone is unpublished, or negatively cached for up to 1800 s after publishing. Publish the records listed in test/fixtures/dns_test_zone.json (see test/fixtures/README.md)"
          end

          published = cloudflare[:records].find { |r| r[:value].start_with?('zone-version ') }
          published = published[:value] unless published.nil? # `?.value`
          if published != marker
            raise "#{zone[:zone]} publishes \"#{published}\" while the fixture is at version #{zone[:version]}: republish the zone from test/fixtures/dns_test_zone.json"
          end

          if !cloudflare[:records].all? { |r| r[:dnssec] == true }
            google = probe.call(Triauth::Resolvers::Google)
            if !google[:records].nil? && google[:records].all? { |r| r[:dnssec] == true }
              warn("[zone] Cloudflare DoH does not validate #{zone[:zone]} while Google does - 1.1.1.1 has not picked up the DS yet (up to an hour per PoP); dnssec assertions fail until it does")
            else
              raise "#{zone[:zone]} is not DNSSEC-validated by Cloudflare or Google DoH - is the DS record for triauthdemo.org at the registrar?"
            end
          end
          # The 40-record name shows whether the resolver path of this machine delivers large answers in
          # full. A short answer fails here, once, instead of in every SystemDns-bearing cell.
          if IS_NODE
            big_name = "big.#{zone[:zone]}"
            short = truncated_by.call(entries[big_name], settle.call(-> { Triauth::Resolvers::SystemDns.new({ timeout: 2000, tries: 2 }).resolve(big_name, 'TXT') }))
            if !short.nil?
              raise truncation_error.call(big_name, short, 'SystemDns')
            end
          end
          :done
        rescue StandardError => err
          err
        end
        raise preflight if preflight.is_a?(Exception)
      end
      before { zone_preflight.call }

      entries.each do |name, entry|
        query = query_name.call(name, entry)

        describe "#{query} - #{entry[:exercises]}" do
          # One round trip per resolver, all in flight together; the cells assert on the outcomes.
          txt = {}
          config = {}
          typed = {}
          wants_config = !entry[:config].nil? || (!entry[:expect].nil? && !entry[:expect][:resolveConfig].nil?)

          # (a mocha `before` runs once: memoized as the preflight is, the first test of the describe fills the cells; the
          # `Promise.all` over the matrix is one Thread per row, the cells written under a Mutex; `this.timeout(20000)` has no counterpart)
          resolved = nil
          cells_mutex = Mutex.new
          resolve_cells = lambda do
            resolved ||= begin
              matrix.map do |r|
                Thread.new do
                  outcome = settle.call(-> { r[:make].call.resolve(query, 'TXT') })
                  cells_mutex.synchronize { txt[r[:label]] = outcome }
                  if wants_config && (r[:kind] != 'node' || !entry[:config].nil?)
                    outcome = settle.call(-> { r[:make].call.resolve_config(query) })
                    cells_mutex.synchronize { config[r[:label]] = outcome }
                  end
                  (entry[:queries].nil? ? {} : entry[:queries]).each_key do |type|
                    outcome = settle.call(-> { r[:make].call.resolve(query, type.to_s) })
                    cells_mutex.synchronize { (typed[type] ||= {})[r[:label]] = outcome }
                  end
                end
              end.each(&:join)
              :done
            end
          end
          before { resolve_cells.call }

          matrix.each do |r|
            exp = expectation_for.call(r[:kind], entry)
            public_send(it_.call(r), "#{r[:label]} resolves TXT to #{summary.call(exp)}") do
              short = r[:kind] != 'doh' ? truncated_by.call(entry, txt[r[:label]]) : nil
              if !short.nil?
                raise truncation_error.call(query, short, r[:label])
              end

              assert_cell.call(self, r[:kind], txt[r[:label]], query, entry, exp)
            end
          end

          if !entry[:config].nil?
            matrix.each do |r|
              public_send(it_.call(r), "#{r[:label]} resolveConfig parses the records as published") do
                outcome = config[r[:label]]
                assert(outcome.key?(:records), "#{query}: resolveConfig rejected with #{outcome[:error]&.message}")
                assert_equal(sorted_config.call(entry[:config]), sorted_config.call(outcome[:records]))
                assert_shape.call(self, r[:kind], outcome[:records], query, entry)
              end
            end
          end

          if !entry[:expect].nil? && !entry[:expect][:resolveConfig].nil?
            matrix.select { |r| r[:kind] != 'node' }.each do |r|
              it "#{r[:label]} resolveConfig surfaces the failure as error #{entry[:expect][:resolveConfig]}" do
                error = config[r[:label]][:error]
                assert(error.is_a?(Triauth::Error) && error.code == entry[:expect][:resolveConfig],
                       "#{query}: expected Triauth.Error #{entry[:expect][:resolveConfig]}, got #{error&.message}")
              end
            end
          end

          (entry[:queries].nil? ? {} : entry[:queries]).each do |type, spec|
            matrix.each do |r|
              exp = expectation_for.call(r[:kind], entry, spec[r[:kind].to_sym])
              public_send(it_.call(r), "#{r[:label]} resolves #{type} to #{summary.call(exp)}") do
                assert_cell.call(self, r[:kind], typed[type][r[:label]], query, entry, exp, strip_dot)
              end
            end
          end
        end
      end

      describe 'the default composition, cross-checked' do
        set_name = "set.#{zone[:zone]}"
        big_name = "big.#{zone[:zone]}"

        it 'keeps every record of an RRset the three members agree on (intersection loses nothing)' do
          records = make_default_composition.call.resolve(set_name, 'TXT')
          assert_equal entries[set_name][:records][:TXT].sort, values.call(records)
          big = make_default_composition.call.resolve(big_name, 'TXT')
          short = truncated_by.call(entries[big_name], { records: big })
          if !short.nil?
            raise truncation_error.call(big_name, short, 'the default composition')
          end

          assert_equal entries[big_name][:records][:TXT].length, big.length
        end

        it 'reports dnssec:true from the validating members alone, node:dns abstaining' do
          records = make_default_composition.call.resolve("plain.#{zone[:zone]}", 'TXT')
          assert_equal 1, records.length
          assert_equal true, records[0][:dnssec]
          assert records[0][:ttl] > 0 && records[0][:ttl] <= zone[:defaults][:ttl]
        end

        it 'rejects a broken DNSSEC chain with the members\' reasons' do
          assert_raises(StandardError) { make_default_composition.call.resolve('dnssec-failed.org', 'TXT') }
          err = assert_raises(Triauth::Error) { make_default_composition.call.resolve_config('dnssec-failed.org') }
          assert_equal 'dns_unavailable', err.code
        end
      end

      describe 'Triauth.Resolvers.CachingResolver over the default composition' do
        # `this.timeout(30000)` has no counterpart

        # Counts what reaches the network; the cache must answer the second query by itself.
        # (`Counting` sits at the top of this file: a class cannot be defined inside a method body)

        it 'serves the second query from the cache with the remaining TTL, and bypasses it on request' do
          name = "plain.#{zone[:zone]}"
          upstream = Counting.new(make_default_composition.call)
          cache = Triauth::Resolvers::CachingResolver.new(upstream)

          first = cache.resolve(name, 'TXT')
          # A record about to expire would leave nothing to serve; take a fresh one instead.
          if first.map { |r| r[:ttl] }.min < 5
            sleep 6 # `await new Promise((resolve) => setTimeout(resolve, 6000))`
            first = cache.resolve(name, 'TXT')
          end
          calls = upstream.calls

          second = cache.resolve(name, 'TXT')
          assert_equal calls, upstream.calls, 'the second query never reaches the network'
          assert_equal values.call(first), values.call(second)
          assert_equal first[0][:dnssec], second[0][:dnssec]
          assert second[0][:ttl] <= first[0][:ttl], 'a cached answer carries the remaining TTL'

          cache.resolve(name, 'TXT', { cache: false })
          assert_equal calls + 1, upstream.calls, 'cache:false goes to the network'
        end
      end
    end
  end
end

TestInternals.resolvers_zone if __FILE__ == $PROGRAM_NAME
