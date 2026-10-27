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


require_relative 'helpers'
require_relative 'validator'
require_relative 'protocol'

module Triauth
  # Holds information about include statements for identifier, as extracted from identity records.
  class IdentityIncludes
    # @return [Hash{Symbol => Object}] The effective settings: the global `Triauth.config` with the constructor's overrides merged over it.
    attr_reader :config
    # @return [Array<Hash>] The include statements, each `{ref, options, use, scope, domainName, tag, expires}`, in publication order until sorted.
    attr_reader :includes
    # @return [Boolean] Whether `includes` is in its canonical (tag-sorted) order.
    attr_reader :sorted

    # Constructs an empty include-statement list.
    #
    # @param config [Hash] optional overrides for the global Triauth.config settings. Defaults to `{}`.
    def initialize(config = {})
      @config = Helpers.merge_config(config)

      # Holds entries in form of {ref, options, use, scope, domainName, tag, expires}
      @includes = []
      @sorted = false
    end

    # Parses the endpoint record's `include` option into the include policy list.
    #
    # @param raw_option [String, nil] the `include` option value as published; nil defaults to `any`.
    #
    # @return [Array<String>] the policy entries (`none`|`any`|`local`|allowlisted domain names), lowercased.
    def self.parse_policy(raw_option = nil)
      # `rawOption !== undefined`: nil takes the JS `undefined` branch (a `null` option would throw there; a DNS option is never null)
      if !raw_option.nil?
        policy = Helpers.ascii_lowercase(raw_option)
        return policy.empty? ? [''] : policy.split(',', -1) # JS `''.split(',')` is `['']`
      end

      return [Protocol::DEFAULT_INCLUDE]
    end

    # Adds an include statement to the list of includes
    #
    # @param value [String] the ref of the include as visible in the identity record - either the actor's
    #        identifier (e.g., 'actor@triauthdemo.org') or its identity domain (e.g., 'actor._at.triauthdemo.org')
    # @param options [Hash] the include options as specified in the identity record. Defaults to `{}`.
    # @param metadata [Hash] the resolve-layer context for the include record (`{expires, includePolicy, localDomainName}`);
    #        `includePolicy` is the endpoint record's `include` option as a list of policies: `none` rejects every include (and dominates any combination),
    #        `any` as the sole entry allows all refs, `local` allows refs on `localDomainName`, and any other entry allowlists that exact domain;
    #        when absent it defaults to `['none']` (every include is ignored). Defaults to `{}`.
    # @return [Boolean] true when the include was successfully added, false when it was ignored (e.g., unrecognized ref or options, or the `LIMITS[:maxIncludes]` cap was exceeded)
    def add(value, options = {}, metadata = {})
      # Work on a private copy of `options`. `Helpers.object_assign` copies a `__proto__` key as data, so the options
      # schema below judges it like any other unknown option
      options = Helpers.object_assign({}, options)

      # Normalize value to downcase
      # (an ill-formed (invalid UTF-8) `value` raises here, where JS folds it and fails the ref grammar; records reach this method `is_normal_string`-validated)
      value = Helpers.ascii_lowercase(value.to_s) # ASCII-only: a non-ASCII uppercase letter must fail the ref grammar, not fold into it

      # The value must be either an identifier (`actor@example.org`) or a lowercase identity domain (`actor._at.example.org`, `_4gibdu58b3._at.example.org`)
      # The separator (`@` or AT_MARKER) tells the two spellings apart,
      separator =
        if Validator.validate_identifier(value)[:valid]
          '@'
        elsif Helpers.is_domain_name(value.sub(/\A_/, '').sub(Protocol::AT_MARKER, '.')) && value.split(Protocol::AT_MARKER, -1).length == 2
          Protocol::AT_MARKER
        end

      if separator.nil?
        Helpers.log(@config, :debug, 'Ignoring include due to unrecognized ref')
        return false
      end

      # Parse options

      # All non-x- prefixed options are critical, and unknown critical options MUST cause include to be ignored.
      # `scope` is required and names the service hosts the grant works at: the sole entry `any` (every host),
      # or a comma-separated allowlist of hostnames. `any` beside other entries and `none` are not valid.
      options_schema = {
        use: [Protocol::FLOWS_USE_REGEXP],
        scope: [lambda do |scope|
          # JS `''.split(',')` is `['']`, so an empty scope is rejected; `-1` keeps the empty slot of `svc.example,`
          scope == Protocol::SCOPE_ANY || (scope.empty? ? [''] : scope.split(',', -1)).all? do |host|
            host != Protocol::SCOPE_ANY && host != Protocol::SCOPE_NONE && Helpers.url_host("https://#{host}/") == host
          end
        end]
      }

      # Set defaults
      options[:use] = Protocol::FLOWS.join(',') if options[:use].nil?

      # `scope` has no safe default
      # (`options['scope'] === undefined` is "member absent": a present nil member goes on to the schema check, which rejects it, as in JS)
      if !options.key?(:scope)
        Helpers.log(@config, :debug, 'Ignoring include without a scope option', { ref: value })
        return false
      end

      # Validate options
      if !Helpers.verify_options_schema(options, options_schema)
        return false
      end

      # Extract domainName from the ref
      domain_name = value.split(separator, -1)[1..].join(separator)

      # Double check that we have extracted non-empty domainName - should be unreachable under normal conditions
      if domain_name.empty?
        return false
      end

      # Check the include policy (the endpoint record's `include` option), as passed from the resolve layer
      include_policy = metadata[:includePolicy].nil? ? ['none'] : metadata[:includePolicy]
      if include_policy.include?('none') ||
         !(
           (include_policy.length == 1 && include_policy[0] == 'any') ||
           (include_policy.include?('local') && domain_name == metadata[:localDomainName]) ||
           include_policy.include?(domain_name)
         )
        Helpers.log(@config, :debug, 'Ignoring include due to policy', { ref: value, includePolicy: include_policy })
        return false
      end

      # Enforce the include count cap - includes beyond it are ignored
      if @includes.length >= Protocol::LIMITS[:maxIncludes]
        Helpers.log(@config, :debug, 'Ignoring include - too many include statements')
        return false
      end

      # A stable tag of this grant (its ref and critical options), so the grant's presence can later be re-checked from the tag alone
      tag = Helpers.sha256(
        "\x01#{value}\x02" +
          options.reject { |k, _| k.to_s[0] == 'x' && k.to_s[1] == '-' }.map { |k, v| "#{k}=#{v}" }.sort.join("\x1E")
      )

      # At this point the `include` has been validated, so we can add it to the list and continue
      @includes.push(
        {
          ref: value,
          options: options,                                                                      # the published spelling - the tag preimage and whois read this
          use: options[:use].split(',', -1),                                                     # parsed once for matching
          scope: options[:scope] == Protocol::SCOPE_ANY ? nil : options[:scope].split(',', -1),  # nil = every service host
          domainName: domain_name,
          tag: tag,
          expires: metadata[:expires]
        }
      )

      @sorted = false

      return true
    end

    # Lists the include statements in their canonical (tag-sorted) order.
    #
    # @return [Array<Hash>] the include statements, each `{ref: String, options: Hash, use: Array<String>, scope: (Array<String>, nil), domainName: String, tag: String, expires: (Integer, nil)}`
    #         (`scope` is `nil` for a `scope=any` grant, which covers every service host); an empty array when the identity publishes none.
    def list
      sort_includes
      return @includes.dup
    end

    # Checks if the include statement references the given actor (by identifier or identity domain), allows the
    # given mode/use, and covers the given service host with its `scope`.
    #
    # @param include_statement [Hash] the include statement to check.
    # @param actor_identity [Triauth::Identity] the resolved actor identity to match against.
    # @param mode [String, nil] the flow the include must allow; `nil` skips the use check.
    # @param host [String, nil] the service host the include must cover; `nil` skips the scope check.
    #
    # @return [Boolean] true when the include statement covers the actor, the mode, and the host.
    def check_match(include_statement, actor_identity, mode, host)
      return (
        (include_statement[:ref] == actor_identity.identifier || include_statement[:ref] == actor_identity.identity_domain.domain_name.downcase) &&
        (mode.nil? || include_statement[:use].include?(mode)) &&
        (host.nil? || include_statement[:scope].nil? || include_statement[:scope].include?(host))
      )
    end
    private :check_match

    # Sorts the include statements by their `tag` values (idempotent).
    #
    # The scan order matters as DNS may return the records in any order, and without the sort the code
    # could pick different includes (with different tags - which end up in deviceTag) on each API method call.
    def sort_includes
      if !@sorted
        @includes.sort! do |a, b|
          x = a[:tag]
          y = b[:tag]
          if x < y
            -1
          elsif x > y
            1
          else
            0
          end
        end
      end

      @sorted = true
    end
    private :sort_includes

    # Finds an include statement that grants the given actor the given mode, resolving the actor's identity in the process.
    #
    # @param actor_identity [Triauth::Identity] the actor (delegate) to match include statements against.
    # @param include_tag [String, nil] when given, only the include statement with this tag is considered. Defaults to nil.
    # @param mode [String, nil] the flow that the include must allow; `nil` skips the use check. Defaults to 'auth'.
    # @param host [String, nil] the service host that the include's `scope` must cover; `nil` skips the scope check. Defaults to nil.
    #
    # @return [Hash, nil, false] the matching include statement, `nil` when none matches (revoked), or `false` when the actor's identity could not be resolved.
    def find(actor_identity, include_tag = nil, mode = 'auth', host = nil)
      sort_includes
      candidates = !include_tag.nil? ? @includes.select { |incl| incl[:tag] == include_tag } : @includes

      if candidates.length == 0
        Helpers.log(@config, :debug, 'IdentityIncludes.find failed - include statement revoked', { includeTag: include_tag })
        return nil
      end

      actor_identity.resolve
      if !actor_identity.resolved
        Helpers.log(@config, :debug, 'IdentityIncludes.find failed - failed to resolve actor', { actorIdentifier: actor_identity.identifier })
        return false
      end

      return candidates.find { |incl| check_match(incl, actor_identity, mode, host) } # the `?? null`: `find` answers nil already
    end
  end
end
