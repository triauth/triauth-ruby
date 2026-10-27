# frozen_string_literal: true

require_relative '../setup'
require 'json'

# A counting inner resolver: tracks upstream calls, supports per-test record changes,
# injected failures, and a settle delay (for the coalescing tests).
class CountingResolverStub < Triauth::Resolvers::Base
  attr_accessor :domain_records, :calls, :error, :delay

  def initialize(domain_records = {})
    super()
    @domain_records = domain_records
    @calls = 0
    @error = nil
    @delay = 0
  end

  # Four parameters, as `Base#resolve_config` passes four; the records map and the record types are keyed by Symbols.
  def resolve(domain_name, type, _options = {}, _config = {})
    @calls += 1

    # `return new Promise(...)` with `setTimeout(..., this.delay)`: the body runs inline after the delay
    sleep(@delay / 1000.0) if @delay > 0
    if !@error.nil?
      raise @error
    end

    # Hand out fresh record objects, like real resolvers do
    return ((@domain_records[domain_name.to_sym] || {})[type.to_sym] || []).map(&:dup)
  end
end

module TestInternals
  # The JS `const REAL_NOW = Date.now` of the describe (a constant cannot be assigned inside a method body, so it sits here)
  REAL_NOW = Triauth::Helpers.method(:date_now) unless defined?(REAL_NOW)

  def self.caching_resolver
    describe 'Triauth.Resolvers.CachingResolver' do
      make_records = -> { { 'cache.test': { TXT: [{ value: 'key AAAA', ttl: 60, dnssec: true }] } } }

      # `Date.now = () => now`: the frozen clock reads `@now` of the running test through the captured instance, so that
      # `@now += ...` inside a test is visible to it (a `before` block and an `it` block are different closures)
      before do
        @now = REAL_NOW.call
        test = self
        Triauth::Helpers.define_singleton_method(:date_now) { test.instance_variable_get(:@now) }
      end

      after do
        Triauth::Helpers.define_singleton_method(:date_now, REAL_NOW)
      end

      it 'serves repeated queries from the cache within the TTL' do
        inner = CountingResolverStub.new(make_records.call)
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        records = resolver.resolve('cache.test', 'TXT')
        assert_equal 1, inner.calls
        assert_equal 'key AAAA', records[0][:value]
        assert_equal 60, records[0][:ttl]
        assert_equal true, records[0][:dnssec]

        @now += 30 * 1000
        records = resolver.resolve('cache.test', 'TXT')
        assert_equal 1, inner.calls, 'second query must be served from the cache'
        assert_equal 'key AAAA', records[0][:value]
        assert_equal true, records[0][:dnssec]
      end

      it 'serves cached records with the remaining, not the original, TTL' do
        inner = CountingResolverStub.new(make_records.call)
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        resolver.resolve('cache.test', 'TXT')

        @now += 25 * 1000
        records = resolver.resolve('cache.test', 'TXT')
        assert_equal 1, inner.calls
        assert_equal 35, records[0][:ttl], 'cached record must report the remaining TTL'
      end

      it 're-queries once the record TTL has passed' do
        inner = CountingResolverStub.new(make_records.call)
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        resolver.resolve('cache.test', 'TXT')

        @now += 60 * 1000
        resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls, 'expired cache entries must not be served'
      end

      it 'caps the cache lifetime at maxTtl' do
        inner = CountingResolverStub.new({ 'cache.test': { TXT: [{ value: 'key AAAA', ttl: 3600, dnssec: true }] } })
        resolver = Triauth::Resolvers::CachingResolver.new(inner, { maxTtl: 10 })

        resolver.resolve('cache.test', 'TXT')

        @now += 9 * 1000
        records = resolver.resolve('cache.test', 'TXT')
        assert_equal 1, inner.calls
        assert_equal 3591, records[0][:ttl], 'the record TTL itself is not capped, only the cache lifetime'

        @now += 1 * 1000
        resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls, 'entries must not be served from the cache for longer than maxTtl'
      end

      it 'uses the shortest TTL across records as the cache lifetime' do
        inner = CountingResolverStub.new(
          { 'cache.test': { TXT:
            [
              { value: 'key AAAA', ttl: 60, dnssec: true },
              { value: 'key BBBB', ttl: 5, dnssec: true }
            ] } }
        )
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        resolver.resolve('cache.test', 'TXT')

        @now += 4 * 1000
        resolver.resolve('cache.test', 'TXT')
        assert_equal 1, inner.calls

        @now += 1 * 1000
        resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls
      end

      it 'does not cache answers with ttl:0 records, and caches nothing when maxTtl is 0' do
        inner = CountingResolverStub.new({ 'cache.test': { TXT: [{ value: 'key AAAA', ttl: 0, dnssec: true }] } })
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        resolver.resolve('cache.test', 'TXT')
        resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls, 'ttl:0 means "do not cache"'

        inner = CountingResolverStub.new(make_records.call)
        resolver = Triauth::Resolvers::CachingResolver.new(inner, { maxTtl: 0 })

        resolver.resolve('cache.test', 'TXT')
        resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls, 'maxTtl:0 must disable caching'
      end

      it 'does not cache records that carry no TTL by default' do
        inner = CountingResolverStub.new({ 'cache.test': { TXT: [{ value: 'key AAAA', ttl: nil, dnssec: nil }] } })
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        resolver.resolve('cache.test', 'TXT')
        resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls
      end

      it 'caches TTL-less records for defaultTtl seconds when configured, keeping their TTL undefined' do
        inner = CountingResolverStub.new({ 'cache.test': { TXT: [{ value: 'key AAAA', ttl: nil, dnssec: nil }] } })
        resolver = Triauth::Resolvers::CachingResolver.new(inner, { defaultTtl: 30 })

        resolver.resolve('cache.test', 'TXT')

        @now += 29 * 1000
        records = resolver.resolve('cache.test', 'TXT')
        assert_equal 1, inner.calls
        assert_nil records[0][:ttl], 'a TTL the origin did not provide must not be invented'
        assert_nil records[0][:dnssec]

        @now += 1 * 1000
        resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls
      end

      it 'does not cache empty answers by default' do
        inner = CountingResolverStub.new({})
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        assert_equal [], resolver.resolve('missing.test', 'TXT')
        assert_equal [], resolver.resolve('missing.test', 'TXT')
        assert_equal 2, inner.calls
      end

      it 'caches empty answers for negativeTtl seconds when configured' do
        inner = CountingResolverStub.new({})
        resolver = Triauth::Resolvers::CachingResolver.new(inner, { negativeTtl: 5 })

        assert_equal [], resolver.resolve('missing.test', 'TXT')
        assert_equal [], resolver.resolve('missing.test', 'TXT')
        assert_equal 1, inner.calls

        @now += 5 * 1000
        resolver.resolve('missing.test', 'TXT')
        assert_equal 2, inner.calls
      end

      it 'never caches failed resolutions' do
        inner = CountingResolverStub.new(make_records.call)
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        inner.error = RuntimeError.new('resolution failed')
        err = assert_raises(RuntimeError) { resolver.resolve('cache.test', 'TXT') }
        assert_match(/resolution failed/, err.message)
        assert_equal 1, inner.calls

        inner.error = nil
        records = resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls, 'the failure must not have been cached'
        assert_equal 'key AAAA', records[0][:value]

        resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls, 'the subsequent success must have been cached'
      end

      it 'bypasses the cache entirely (no read, no write) when called with cache:false' do
        inner = CountingResolverStub.new({ 'cache.test': { TXT: [{ value: 'key OLD', ttl: 60, dnssec: true }] } })
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        resolver.resolve('cache.test', 'TXT') # populates the cache with 'key OLD'
        inner.domain_records[:'cache.test'][:TXT] = [{ value: 'key NEW', ttl: 60, dnssec: true }]

        fresh = resolver.resolve('cache.test', 'TXT', { cache: false })
        assert_equal 2, inner.calls, 'cache:false must not read from the cache'
        assert_equal 'key NEW', fresh[0][:value]

        cached = resolver.resolve('cache.test', 'TXT')
        assert_equal 2, inner.calls
        assert_equal 'key OLD', cached[0][:value], 'cache:false must not write to the cache'
      end

      it 'keys the cache by record type and domain name, case-insensitively for the type' do
        inner = CountingResolverStub.new({
                                           'a.test': { TXT: [{ value: 'key AAAA', ttl: 60, dnssec: true }], A: [{ value: '192.0.2.1', ttl: 60, dnssec: true }] },
                                           'b.test': { TXT: [{ value: 'key BBBB', ttl: 60, dnssec: true }] }
                                         })
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        assert_equal 'key AAAA', resolver.resolve('a.test', 'TXT')[0][:value]
        assert_equal '192.0.2.1', resolver.resolve('a.test', 'A')[0][:value]
        assert_equal 'key BBBB', resolver.resolve('b.test', 'TXT')[0][:value]
        assert_equal 3, inner.calls, 'different domains/types must not collide in the cache'

        assert_equal 'key AAAA', resolver.resolve('a.test', 'txt')[0][:value]
        assert_equal '192.0.2.1', resolver.resolve('a.test', 'A')[0][:value]
        assert_equal 'key BBBB', resolver.resolve('b.test', 'TXT')[0][:value]
        assert_equal 3, inner.calls, 'repeated queries (incl. differently-cased types) must be served from the cache'
      end

      it 'coalesces concurrent queries for the same records into a single upstream query' do
        inner = CountingResolverStub.new(make_records.call)
        inner.delay = 20
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        # `Promise.all([...])`: one Thread per concurrent caller, joined through `value`
        r1, r2 = [
          Thread.new { resolver.resolve('cache.test', 'TXT') },
          Thread.new { resolver.resolve('cache.test', 'TXT') }
        ].map(&:value)

        assert_equal 1, inner.calls, 'concurrent queries must share a single upstream call'
        assert_equal 'key AAAA', r1[0][:value]
        assert_equal 'key AAAA', r2[0][:value]
        refute_same r1[0], r2[0], 'each caller must get its own copy of the records'
      end

      it 'shares a coalesced failure with all waiting callers, without caching it' do
        inner = CountingResolverStub.new(make_records.call)
        inner.delay = 20
        inner.error = RuntimeError.new('resolution failed')
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        # `Promise.allSettled([...])`: each Thread settles into `[:fulfilled, records]` or `[:rejected, error]`
        settled = [
          Thread.new do
            [:fulfilled, resolver.resolve('cache.test', 'TXT')]
          rescue StandardError => e
            [:rejected, e]
          end,
          Thread.new do
            [:fulfilled, resolver.resolve('cache.test', 'TXT')]
          rescue StandardError => e
            [:rejected, e]
          end
        ].map(&:value)

        assert_equal 1, inner.calls
        assert_equal :rejected, settled[0][0]
        assert_equal :rejected, settled[1][0]

        inner.error = nil
        assert_equal 'key AAAA', resolver.resolve('cache.test', 'TXT')[0][:value]
        assert_equal 2, inner.calls
      end

      # 'does not coalesce queries that carry an abort signal' is not ported: there is no caller signal

      it 'is immune to mutations of the records it returned' do
        inner = CountingResolverStub.new(make_records.call)
        resolver = Triauth::Resolvers::CachingResolver.new(inner)

        # Mutate the freshly resolved answer, the way an enclosing MultiResolver would
        fresh = resolver.resolve('cache.test', 'TXT')
        fresh[0][:value] = 'key EVIL'
        fresh[0][:ttl] = 1
        fresh[0][:dnssec] = false

        cached = resolver.resolve('cache.test', 'TXT')
        assert_equal 1, inner.calls
        assert_equal 'key AAAA', cached[0][:value]
        assert_equal 60, cached[0][:ttl]
        assert_equal true, cached[0][:dnssec]

        # Mutating a cache-hit answer must not corrupt the cache either
        cached[0][:dnssec] = false
        assert_equal true, resolver.resolve('cache.test', 'TXT')[0][:dnssec]
      end

      it 'supports a custom asynchronous store with serialization (e.g., Redis-like)' do
        backing = {}
        ops = []
        # The store contract of the port: `get`/`set` are synchronous, and a store that serializes its values restores
        # the Symbol keys of the entry with `symbolize_names: true`
        store = Object.new
        store.define_singleton_method(:get) do |key|
          ops.push(['get', key])
          backing.key?(key) ? JSON.parse(backing[key], symbolize_names: true) : nil
        end
        store.define_singleton_method(:set) do |key, value|
          ops.push(['set', key])
          backing[key] = JSON.generate(value)
        end

        inner = CountingResolverStub.new(make_records.call)
        resolver = Triauth::Resolvers::CachingResolver.new(inner, { store: store })

        resolver.resolve('cache.test', 'TXT')

        @now += 10 * 1000
        records = resolver.resolve('cache.test', 'TXT')
        assert_equal 1, inner.calls, 'the answer must survive the store serialization round-trip'
        assert_equal 'key AAAA', records[0][:value]
        assert_equal 50, records[0][:ttl]
        assert_equal true, records[0][:dnssec]

        assert_equal [['get', 'TXT:cache.test'], ['set', 'TXT:cache.test'], ['get', 'TXT:cache.test']], ops
      end

      it 'fails open (to a fresh resolution) when the store fails or returns garbage' do
        inner = CountingResolverStub.new(make_records.call)

        # A store that always throws
        failing_store = Object.new
        failing_store.define_singleton_method(:get) { |_key| raise 'store read failed' }
        failing_store.define_singleton_method(:set) { |_key, _value| raise 'store write failed' }
        resolver = Triauth::Resolvers::CachingResolver.new(inner, { store: failing_store })

        assert_equal 'key AAAA', resolver.resolve('cache.test', 'TXT')[0][:value]
        assert_equal 'key AAAA', resolver.resolve('cache.test', 'TXT')[0][:value]
        assert_equal 2, inner.calls, 'a failing store must not break resolution'

        # A store that returns malformed entries
        ['garbage', {}, { records: [], storedAt: 'x', expiresAt: 'y' }, 42].each do |garbage|
          inner.calls = 0
          garbage_store = Object.new
          garbage_store.define_singleton_method(:get) { |_key| garbage }
          garbage_store.define_singleton_method(:set) do |_key, _value|
            # `set: () => {}`: a store that writes nothing
          end
          resolver = Triauth::Resolvers::CachingResolver.new(inner, { store: garbage_store })

          assert_equal 'key AAAA', resolver.resolve('cache.test', 'TXT')[0][:value]
          assert_equal 1, inner.calls, "a malformed cache entry (#{JSON.generate(garbage)}) must be treated as a miss"
        end
      end

      it 'integrates with resolveConfig and the recommended MultiResolver composition' do
        inner_a = CountingResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA opt=1', ttl: 20, dnssec: true }] } })
        inner_b = CountingResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA opt=1', ttl: 10, dnssec: true }] } })

        resolver = Triauth::Resolvers::CachingResolver.new(
          Triauth::Resolvers::MultiResolver.new([inner_a, inner_b], { maxFailures: 0 })
        )

        entries = resolver.resolve_config('config.test')
        assert_equal 1, entries.length
        assert_equal 'key', entries[0][:key]
        assert_equal 'AAAA', entries[0][:value]
        assert_equal '1', entries[0][:options][:opt]
        assert_equal 10, entries[0][:ttl]
        assert_equal true, entries[0][:dnssec]

        @now += 5 * 1000
        entries = resolver.resolve_config('config.test')
        assert_equal 1, inner_a.calls
        assert_equal 1, inner_b.calls, 'one cache hit must save the queries to all wrapped providers'
        assert_equal 5, entries[0][:ttl], 'remaining TTL must propagate through resolveConfig'
      end
    end
  end
end

TestInternals.caching_resolver if __FILE__ == $PROGRAM_NAME
