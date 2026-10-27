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


require_relative 'base'
require_relative '../helpers'

module Triauth
  module Resolvers
    # A caching resolver that wraps another resolver (a descendant of Triauth::Resolvers::Base) and caches its
    # answers at the application level, so that repeated queries for the same DNS records are served from the
    # cache instead of the network.
    #
    # @example
    #   Triauth.config[:resolver] = Triauth::Resolvers::CachingResolver.new(Triauth.config[:resolver])
    class CachingResolver < Base
      # @return [Base] the wrapped resolver.
      attr_reader :resolver
      # @return [Hash] the options passed to the constructor.
      attr_reader :options
      # @return [Object] the cache store (`options[:store]`, or the default LRU cache).
      attr_reader :store
      # @return [Hash{String => Thread}] the in-flight lookups by cache key.
      attr_reader :pending

      # @param resolver [Base] The resolver (a descendant of Triauth::Resolvers::Base) whose answers should be cached.
      # @param options [Hash] Defaults to `{}`.
      # @option options [Object] :store The cache store to use, fixed at construction time. May be anything that implements
      #   `get(key)` and `set(key, value)` methods (synchronous here: they return their value directly, there are no
      #   Promises); stored values are JSON-serializable and must survive the store's serialization round-trip, so a
      #   store that serializes its values must restore Symbol keys (`JSON.parse(..., symbolize_names: true)`).
      #   Defaults to an in-process `Triauth::Helpers.create_lru_cache(1000)`.
      #   SECURITY: the store becomes part of your trusted computing base — anyone able to write to it
      #   can inject DNS records (i.e., public keys). When using a shared store such as Redis,
      #   restrict write access accordingly.
      # @option options [Integer] :maxTtl The maximal time (in seconds) an answer may be served from the cache, regardless of the TTLs
      #   carried by its records. Bounds the worst-case revocation latency added on top of regular
      #   DNS caching. Defaults to 300. Set to 0 to disable caching.
      # @option options [Integer] :defaultTtl The cache lifetime (in seconds) for answers whose records carry no TTL (every built-in
      #   resolver reports one, SystemDns included; a custom resolver may not). Defaults to 0 (such answers are not cached).
      # @option options [Integer] :negativeTtl The cache lifetime (in seconds) for empty answers (no records found).
      #   Defaults to 0 (empty answers are not cached).
      def initialize(resolver, options = {})
        super()
        @resolver = resolver
        @options = options
        @store = options[:store] || Helpers.create_lru_cache(1000)
        @pending = {}
        @pending_mutex = Mutex.new # guards `@pending` (the JS Map is touched from one event loop; the Threads here are not)
      end

      # Queries the cache for resource records of a given type that are stored under a given domain_name,
      # falling back to (and caching the answer of) the wrapped resolver on a cache miss.
      #
      # @param domain_name [String] A domain name to query the DNS for. For example "example.com".
      # @param type [String] A type of DNS resource record to look for. For example "TXT", or "A".
      # @param options [Hash] Per-call overrides for the options passed to the constructor (except `store`).
      #   Additionally, `cache` may be set to `false` to fully bypass the cache for this
      #   call (no read, no write). All options are also forwarded to the wrapped resolver. Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Array<Hash>] The array of retrieved DNS resource records in `{value, ttl, dnssec}` format
      #   (`ttl` an Integer or nil, `dnssec` a Boolean or nil).
      def resolve(domain_name, type, options = {}, config = {})
        config = Helpers.merge_config(config)

        options = Helpers.object_assign({
                                          maxTtl: 300,
                                          defaultTtl: 0,
                                          negativeTtl: 0
                                        }, @options, options)

        # Ensure type is upper-case, so that cache keys are consistent across differently-cased queries
        type = type.to_s.upcase

        if options[:cache] == false
          return @resolver.resolve(domain_name, type, options, config)
        end

        key = "#{type}:#{domain_name}"

        # The cache must fail open (to a fresh resolution): a failing store is treated as a cache miss
        entry = nil
        begin
          entry = @store.get(key)
        rescue StandardError => err
          Helpers.log(config, :debug, "[DNS] Cache read failed for #{type} records of #{domain_name}", { cause: err })
        end

        now = Helpers.date_now
        # `entry && ...`: a String or an Integer entry has no members, so `is_a?(Hash)` is the whole guard
        if entry.is_a?(Hash) && entry[:records].is_a?(Array) && Helpers.is_number(entry[:storedAt]) && Helpers.is_number(entry[:expiresAt]) && now < entry[:expiresAt]
          Helpers.log(config, :debug, "[DNS] Cache hit for #{type} records of #{domain_name}")

          # Serve records with the remaining — not the original — TTL, so that TTL-derived
          # values downstream (e.g., the `expires` timestamps) stay honest
          elapsed = (now - entry[:storedAt]) / 1000.0 # a float division, as the JS `/ 1000`

          return entry[:records].map do |record|
            {
              value: record[:value],
              ttl: Helpers.is_number(record[:ttl]) ? [0, (record[:ttl] - elapsed).ceil].max : nil,
              dnssec: record[:dnssec]
            }
          end
        end

        # Coalesce concurrent cache misses for the same key into a single upstream query.
        # Callers with an abort signal always get their own upstream query, so that one
        # caller's abort cannot reject a resolution shared with the others.
        # (there is no abort signal here, so every caller joins the in-flight query; the read and the create below run
        # under one `synchronize` so that two concurrent misses never start two upstream queries)
        lookup = nil
        @pending_mutex.synchronize do
          lookup = @pending[key]

          if !lookup.nil?
            Helpers.log(config, :debug, "[DNS] Joining the in-flight query for #{type} records of #{domain_name}")

          else
            # the in-flight lookup is a Thread (the pending promise): `Thread#value` hands its records to every joiner and
            # re-raises its exception to each of them; the `ensure` is the JS `lookup.then(cleanup, cleanup)`
            lookup = Thread.new do
              Thread.current.report_on_exception = false
              begin
                lookup(key, domain_name, type, options, config)
              ensure
                @pending_mutex.synchronize { @pending.delete(key) }
              end
            end

            # `if (!options.signal)`: no signal exists, so every lookup is registered
            @pending[key] = lookup
          end
        end

        # Each caller gets its own copy of the answer, so that downstream in-place record
        # mutations (e.g., by an enclosing MultiResolver) cannot leak across callers
        return copy_records(lookup.value)
      end

      private

      # Resolves through the wrapped resolver and caches the answer for min(shortest record TTL, maxTtl) seconds.
      # Rejections are propagated and never cached.
      def lookup(key, domain_name, type, options, config)
        records = @resolver.resolve(domain_name, type, options, config)

        # lifetime: for how long (in seconds) the answer may be served from the cache

        if records.length == 0
          lifetime = options[:negativeTtl]

        else
          lifetime = options[:maxTtl]

          records.each do |record|
            lifetime = [lifetime, Helpers.is_number(record[:ttl]) ? record[:ttl] : options[:defaultTtl]].min
          end
        end

        if lifetime > 0
          stored_at = Helpers.date_now

          begin
            # A copy is stored, so that callers mutating the returned records cannot corrupt the cache
            @store.set(key, { records: copy_records(records), storedAt: stored_at, expiresAt: stored_at + (lifetime * 1000) })
            Helpers.log(config, :debug, "[DNS] Cached #{records.length} #{type} record(s) of #{domain_name} for #{lifetime}s")
          rescue StandardError => err
            Helpers.log(config, :debug, "[DNS] Cache write failed for #{type} records of #{domain_name}", { cause: err })
          end
        end

        return records
      end

      # The JS `static #copyRecords` is a private instance method here: Ruby cannot call a private class method with an explicit receiver.
      #
      # @param records [Array<Hash>] The records to copy.
      #
      # @return [Array<Hash>] fresh `{value, ttl, dnssec}` Hashes.
      def copy_records(records)
        return records.map { |record| { value: record[:value], ttl: record[:ttl], dnssec: record[:dnssec] } }
      end
    end
  end
end
