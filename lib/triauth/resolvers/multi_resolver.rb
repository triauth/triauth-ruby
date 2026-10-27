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
    # A multi-resolver that takes an array of resolvers, and returns an intersection of DNS resource record values
    # as returned by each of the listed resolvers. This allows responses from multiple independent DNS resolver service
    # providers to be cross-validated against each other, helping to protect from BGP poisoning, rogue providers and provider-specific attacks.
    #
    # The TTL of each record is calculated as a minimal TTL returned by the resolvers.
    # The dnssec property for returned record is set to true only when at least one resolver has set it to 'true' and no resolvers have set it to 'false'.
    # The aggregation is independent of resolver order: resolvers that report no DNSSEC status (nil) express no opinion,
    # and the property remains nil when no resolver reports an explicit status.
    class MultiResolver < Base
      # The carrier of the rejection value of `MultiResolver#resolve`: triauth-js rejects with an Array of the
      # sub-resolver errors, and Ruby raises exceptions only, so that Array travels in `reasons`.
      class ResolutionError < StandardError
        # @return [Array<Exception>] the errors raised by the failed sub-resolvers, in resolver order.
        attr_reader :reasons

        # @param reasons [Array<Exception>] The errors raised by the failed sub-resolvers.
        def initialize(reasons)
          @reasons = reasons
          super("MultiResolver: #{reasons.length} resolver(s) failed: #{reasons.map { |r| r.respond_to?(:message) ? r.message : r.to_s }.join('; ')}")
        end
      end

      # @return [Array<Base>] the resolvers queried by every `resolve` call.
      attr_reader :resolvers
      # @return [Hash] the options passed to the constructor.
      attr_reader :options

      # @param resolvers [Array<Base>] An array of resolver objects (descendants of Triauth::Resolvers::Base).
      # @param options [Hash] The options listed below are consumed at this layer; any other entries
      #   are forwarded to each sub-resolver's resolve() call. Defaults to `{}`.
      # @option options [Integer] :maxFailures The maximal number of resolvers that are allowed to fail for the resolution to still successfully complete.
      # @option options [Integer] :timeout How long to wait (ms) before aborting the multi-resolver call with a timeout error.
      #   A sub-resolver still running at that deadline is left to finish on its own timeouts and its answer is discarded.
      def initialize(resolvers, options = {})
        super()
        @resolvers = resolvers
        @options = options
      end

      # Queries every configured resolver for the given records, and returns the intersection of their answers.
      #
      # A record is returned only when every resolver that answered carries it. Its `ttl` is the lowest one
      # reported for it, and its `dnssec` follows the aggregation described in the class documentation above.
      #
      # @param domain [String] A domain name to query the DNS for.
      # @param type [String] A type of DNS resource record to look for (e.g., 'TXT', 'A').
      # @param options [Hash] Per-call overrides for the resolver options passed to the constructor.
      #   `maxFailures` and `timeout` are consumed at this layer; every other entry
      #   fans out to each sub-resolver's resolve() call. Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Array<Hash>] The array of retrieved DNS resource records in `{value, ttl, dnssec}` format
      #   (`ttl` an Integer or nil, `dnssec` a Boolean or nil).
      #
      # @raise [ResolutionError] carrying the Array of the sub-resolver errors once more than `options[:maxFailures]`
      #   of them fail or none of them answers.
      # @raise [RuntimeError] 'MultiResolver timeout' once `options[:timeout]` elapses.
      def resolve(domain, type, options = {}, config = {})
        config = Helpers.merge_config(config)
        options = Helpers.object_assign({}, @options, options)

        # `return new Promise((multiResolve, multiReject) => {...})`: the promise body runs inline below; `multiResolve(x)` is `return x`, `multiReject(err)` is `raise`
        results = [] # one Thread per sub-resolver (the JS array of promises)

        # Handle timeouts through a deadline: the AbortController and its timer have no counterpart, a sub-resolver still
        # running at the deadline is left to finish on its own timeouts and its answer is discarded (nil and 0 mean no deadline, as `if (options.timeout)`)
        deadline = options[:timeout].nil? || options[:timeout] == 0 ? nil : Helpers.now + options[:timeout]

        # maxFailures and timeout are consumed at this layer; every other option fans out
        # to the sub-resolvers, with the shared abort signal replacing any caller-provided one
        child_options = Helpers.object_assign({}, options)
        child_options.delete(:maxFailures)
        child_options.delete(:timeout)
        # the `childOptions.signal` branches have no counterpart: no `:signal` key ever exists

        @resolvers.each do |resolver|
          results.push(Thread.new do
            Thread.current.report_on_exception = false
            resolver_name = resolver.class.name.to_s.split('::').last # `resolver.constructor.name` (an anonymous class prints as '' there too)
            Helpers.log(config, :debug, "[DNS] Querying resolver #{resolver_name} for #{type} records of #{domain}")
            ts = Helpers.now

            begin
              res = resolver.resolve(domain, type, child_options, config)
              Helpers.log(config, :debug, "[DNS] Resolved #{res.length} record(s) with #{resolver_name} in #{(Helpers.now - ts).round}ms", { res: res })
              [:fulfilled, res]
            rescue StandardError => err
              Helpers.log(config, :debug, "[DNS] Failed resolution with #{resolver_name} in #{(Helpers.now - ts).round}ms", { cause: err })
              [:rejected, err]
            end
          end)
        end

        # the port of `Promise.allSettled(results).then((values) => ...)`: each Thread is joined with the time left to the
        # deadline; a Thread still running at the deadline is left to finish on its own resolver timeouts and its answer is
        # discarded, and the call fails as the JS `multiReject(new Error('MultiResolver timeout'))` does
        values = results.map do |thread|
          joined = deadline.nil? ? thread.join : thread.join([(deadline - Helpers.now) / 1000.0, 0].max)
          raise 'MultiResolver timeout' if joined.nil?

          thread.value
        end

        # `clearTimeout(timeoutHandle)` has no counterpart: no timer is armed

        failed_resolutions = values.select do |v|
          v[0] != :fulfilled
        end

        fulfilled_resolutions = values.select do |v|
          v[0] == :fulfilled
        end

        # Enforce the maxFailures limit from options
        if failed_resolutions.length > (options[:maxFailures].nil? || options[:maxFailures] == 0 ? 0 : options[:maxFailures]) || fulfilled_resolutions.length <= 0
          raise(ResolutionError, failed_resolutions.map { |fr| fr[1] })
        end

        # Start with the first result, and limit/modify it basing on other
        retval = fulfilled_resolutions[0][1]

        # Remove entries which values are not present in responses of _all_ fulfilled resolvers
        fulfilled_resolutions.each do |v|
          retval = retval.select do |record|
            rv = v[1].map do |e|
              e[:value]
            end.include?(record[:value])

            if !rv
              Helpers.log(config, :debug, '[DNS] Ignoring DNS record for which non-matching responses were received', { record: record })
            end

            rv
          end
        end

        # Modify dnssec and ttl properties
        retval.each do |e|
          # Track explicit per-record dnssec reports across all fulfilled resolvers
          saw_true = false
          saw_false = false

          fulfilled_resolutions.each do |v|
            v[1].each do |r|
              if r[:value] == e[:value]

                # Any defined non-true report counts as an explicit veto
                # (`r.dnssec !== undefined`: a nil dnssec is "no opinion", the JS `null` veto cannot be expressed by Ruby data)
                if r[:dnssec] == true
                  saw_true = true
                elsif !r[:dnssec].nil?
                  saw_false = true
                end

                # e.ttl and/or r.ttl may be undefined; ?? keeps a TTL of 0 in the min-aggregation
                # (`undefined < number` is false in JS: a record without a TTL never lowers the min)
                if !r[:ttl].nil? && r[:ttl] < (e[:ttl].nil? ? Float::INFINITY : e[:ttl])
                  e[:ttl] = r[:ttl]
                end

              end
            end
          end

          # dnssec is true only when at least one resolver explicitly reported true and
          # none reported false; it stays nil when no resolver expressed an opinion.
          e[:dnssec] = if saw_false
                         false
                       elsif saw_true
                         true
                       end
        end

        return retval
      end
    end
  end
end
