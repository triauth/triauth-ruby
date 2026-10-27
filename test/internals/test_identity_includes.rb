# frozen_string_literal: true

require_relative '../setup'
require_relative '../stubs/dns_resolver'

module TestInternals
  def self.identity_includes
    actor_key = 'BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8'

    # A resolver stub serving one actor identity, used by the find() tests below.
    actor_resolver = lambda do
      DnsResolverStub.new(
        {
          'actor.example': { TXT: ['triauth auth.actor.example mode=public'] },
          'actor._at.actor.example': { TXT: ["key server[1/1]:#{actor_key}"] }
        }
      )
    end

    any = { includePolicy: ['any'] }

    # Every grant publishes a scope; `any_scope` spells the sole-entry form that covers every service host.
    any_scope = ->(options = {}) { { scope: 'any' }.merge(options) }

    describe 'Triauth.IdentityIncludes' do
      describe 'Triauth.IdentityIncludes.parsePolicy' do
        it 'defaults an unpublished include option to any' do
          assert_equal ['any'], Triauth::IdentityIncludes.parse_policy(nil)
        end

        it 'splits and lowercases the published option' do
          assert_equal ['local', 'partner.example'], Triauth::IdentityIncludes.parse_policy('LOCAL,Partner.Example')
          assert_equal ['any'], Triauth::IdentityIncludes.parse_policy('any')
          assert_equal ['none'], Triauth::IdentityIncludes.parse_policy('none')
        end
      end

      describe 'Triauth.IdentityIncludes.add' do
        describe 'include policy' do
          it 'accepts any ref under a sole any policy' do
            inc = Triauth::IdentityIncludes.new
            assert_equal true, inc.add('a@other.example', any_scope.call, any)
          end

          it 'rejects every ref when the policy is absent (fail closed)' do
            inc = Triauth::IdentityIncludes.new
            assert_equal false, inc.add('a@other.example', any_scope.call)
            assert_equal 0, inc.includes.length
          end

          it 'none rejects every ref and dominates any combination' do
            inc = Triauth::IdentityIncludes.new
            assert_equal false, inc.add('a@other.example', any_scope.call, { includePolicy: ['none'] })
            assert_equal false, inc.add('a@other.example', any_scope.call, { includePolicy: %w[none any] })
            assert_equal false, inc.add('a@other.example', any_scope.call, { includePolicy: ['none', 'other.example'] })
          end

          it 'local admits only refs on localDomainName' do
            inc = Triauth::IdentityIncludes.new
            meta = { includePolicy: ['local'], localDomainName: 'subject.example' }
            assert_equal true, inc.add('a@subject.example', any_scope.call, meta)
            assert_equal false, inc.add('a@other.example', any_scope.call, meta)
          end

          it 'domain entries act as an exact allowlist' do
            inc = Triauth::IdentityIncludes.new
            meta = { includePolicy: ['local', 'partner.example'], localDomainName: 'subject.example' }
            assert_equal true, inc.add('a@partner.example', any_scope.call, meta)
            assert_equal false, inc.add('a@sub.partner.example', any_scope.call, meta)
          end

          it 'any is honored only as the sole policy entry' do
            inc = Triauth::IdentityIncludes.new
            meta = { includePolicy: ['any', 'partner.example'], localDomainName: 'subject.example' }
            assert_equal true, inc.add('a@partner.example', any_scope.call, meta)
            assert_equal false, inc.add('a@other.example', any_scope.call, meta)
          end
        end

        describe 'ref forms' do
          it 'accepts identifier refs, lowercasing them' do
            inc = Triauth::IdentityIncludes.new
            assert_equal true, inc.add('Actor@Example.com', any_scope.call, any)
            assert_equal 'actor@example.com', inc.includes[0][:ref]
            assert_equal 'example.com', inc.includes[0][:domainName]
          end

          it 'accepts identity-domain refs, public and private (leading underscore) forms' do
            inc = Triauth::IdentityIncludes.new
            assert_equal true, inc.add('actor._at.corp.example', any_scope.call, any)
            assert_equal true, inc.add('_4GIBDU53B3._at.private.corp.example', any_scope.call, any)
            assert_equal '_4gibdu53b3._at.private.corp.example', inc.includes[1][:ref]
            assert_equal 'private.corp.example', inc.includes[1][:domainName]
          end

          it 'rejects refs with interior underscores, doubled ._at. markers, or no marker at all' do
            inc = Triauth::IdentityIncludes.new
            assert_equal false, inc.add('_a_l_i_c_e._at.corp.example', any_scope.call, any)
            assert_equal false, inc.add('actor._at.corp._at.example.com', any_scope.call, any)
            assert_equal false, inc.add('corp.example', any_scope.call, any)
            assert_equal 0, inc.includes.length
          end
        end

        describe 'options' do
          it 'defaults an absent use option to every flow' do
            inc = Triauth::IdentityIncludes.new
            assert_equal true, inc.add('a@x.example', any_scope.call, any)
            assert_equal 'attest,auth,ping,sign,stamp', inc.includes[0][:options][:use]
          end

          it 'rejects an explicitly empty or invalid use option (fail closed, no default substitution)' do
            inc = Triauth::IdentityIncludes.new
            assert_equal false, inc.add('a@x.example', any_scope.call({ use: '' }), any)
            assert_equal false, inc.add('a@x.example', any_scope.call({ use: 'bogus' }), any)
            assert_equal 0, inc.includes.length
          end

          it 'rejects unknown critical options and keeps x- experimental ones' do
            inc = Triauth::IdentityIncludes.new
            assert_equal false, inc.add('a@x.example', any_scope.call({ evil: '1' }), any)
            assert_equal true, inc.add('a@x.example', any_scope.call({ 'x-note': 'hello' }), any)
          end

          it 'does not mutate the caller-supplied options object' do
            inc = Triauth::IdentityIncludes.new
            options = any_scope.call
            inc.add('a@x.example', options, any)
            assert_equal({ scope: 'any' }, options)
          end
        end

        describe 'the scope option' do
          it 'accepts a host allowlist, storing the published spelling in options and the parsed form beside it' do
            inc = Triauth::IdentityIncludes.new
            assert_equal true, inc.add('a@x.example', { scope: 'svc.example' }, any)
            assert_equal 'svc.example', inc.includes[0][:options][:scope]
            assert_equal ['svc.example'], inc.includes[0][:scope]
            assert_equal %w[attest auth ping sign stamp], inc.includes[0][:use]
          end

          it 'ignores a record publishing no scope option (fail closed, no default)' do
            inc = Triauth::IdentityIncludes.new
            assert_equal false, inc.add('a@x.example', {}, any)
            assert_equal false, inc.add('a@x.example', { use: 'sign' }, any)
            assert_equal 0, inc.includes.length
          end

          it 'accepts any as the sole entry: options keep the literal spelling and the parsed scope is null (every service host)' do
            inc = Triauth::IdentityIncludes.new
            assert_equal true, inc.add('a@x.example', { scope: 'any' }, any)
            assert_equal 'any', inc.includes[0][:options][:scope]
            assert_nil inc.includes[0][:scope]
          end

          it 'accepts multi-entry lists with duplicates, IPv4 quads, and single-label hosts' do
            inc = Triauth::IdentityIncludes.new
            assert_equal true, inc.add('a@x.example', { scope: 'a.example,b.example,a.example' }, any)
            assert_equal ['a.example', 'b.example', 'a.example'], inc.includes[0][:scope]
            assert_equal true, inc.add('b@x.example', { scope: '10.0.0.5,localhost' }, any)
          end

          it 'rejects the record whenever any entry is not a canonical callback host (fail closed, never repaired)' do
            inc = Triauth::IdentityIncludes.new
            [
              '',                        # empty value - like an empty use, never defaulted
              'SVC.Example',             # hosts are lowercase
              'ANY',                     # values are literal and case-sensitive - the sole-entry keyword included
              'Any',
              'svc.example:8443',        # a port is not part of a host - scope matching is port-blind
              'xn--mller-kva.de',        # no Punycode labels, valid encodings included
              'bad.123',                 # a numeric final label is never a named host
              '0x7f.0.0.1',              # exotic IPv4 spellings match no production
              'svc.example,',            # an empty list slot
              ',svc.example',
              'svc.example,|garbage|',   # one bad entry drops the whole record
              'svc.example/path',        # a path is not a host
              'a..b'
            ].each do |scope|
              assert_equal false, inc.add('a@x.example', { scope: scope }, any), "scope=#{scope}"
            end
            assert_equal 0, inc.includes.length
          end

          it 'rejects a non-string scope value' do
            inc = Triauth::IdentityIncludes.new
            assert_equal false, inc.add('a@x.example', { scope: 42 }, any)
            assert_equal false, inc.add('a@x.example', { scope: ['svc.example'] }, any)
          end

          it 'rejects none anywhere and any beside other entries - any is only the sole-entry spelling' do
            inc = Triauth::IdentityIncludes.new
            ['none', 'any,svc.example', 'svc.example,any', 'none,svc.example', 'any,none', 'any,any'].each do |scope|
              assert_equal false, inc.add('a@x.example', { scope: scope }, any), "scope=#{scope}"
            end
            assert_equal 0, inc.includes.length
          end
        end

        describe 'grant tags' do
          # a method, not a lambda: a lambda in a describe body cannot assert (its `self` is the spec class)
          define_method(:tag_for) do |options|
            inc = Triauth::IdentityIncludes.new
            assert_equal true, inc.add('actor@x.example', options, any)
            inc.includes[0][:tag]
          end

          it 'derives a stable 43-character tag from the ref and critical options only' do
            a = Triauth::IdentityIncludes.new
            b = Triauth::IdentityIncludes.new
            a.add('actor@x.example', any_scope.call({ use: 'sign' }), any)
            b.add('actor@x.example', any_scope.call({ use: 'sign', 'x-note': 'ignored' }), any)
            assert_equal 43, a.includes[0][:tag].length
            assert_equal b.includes[0][:tag], a.includes[0][:tag]

            c = Triauth::IdentityIncludes.new
            c.add('actor@x.example', any_scope.call({ use: 'auth' }), any)
            refute_equal c.includes[0][:tag], a.includes[0][:tag]
          end

          it 'folds the published scope into the tag - scope=any and a host list never share a tag' do
            unrestricted = tag_for({ use: 'sign', scope: 'any' })
            scoped = tag_for({ use: 'sign', scope: 'svc.example' })
            refute_equal scoped, unrestricted
            refute_equal tag_for({ use: 'sign', scope: 'other.example' }), scoped
            assert_equal tag_for({ use: 'sign', scope: 'svc.example' }), scoped
          end

          it 'hashes the literal scope=any pair into the grant tag preimage' do
            assert_equal(
              Triauth::Helpers.sha256("\x01actor@x.example\x02scope=any\x1Euse=sign"),
              tag_for({ use: 'sign', scope: 'any' })
            )
          end
        end

        describe 'the maxIncludes cap' do
          it 'accepts LIMITS.maxIncludes grants and skips (only) the excess, without paying their hash' do
            inc = Triauth::IdentityIncludes.new
            Triauth::LIMITS[:maxIncludes].times do |i|
              assert_equal true, inc.add("a#{i}@x.example", any_scope.call, any)
            end
            assert_equal Triauth::LIMITS[:maxIncludes], inc.includes.length

            # the `crypto.subtle.digest` counter: the port hashes through `Triauth::Helpers.sha256`
            digests = 0
            real_digest = Triauth::Helpers.method(:sha256)
            Triauth::Helpers.define_singleton_method(:sha256) do |*args|
              digests += 1
              real_digest.call(*args)
            end
            begin
              assert_equal false, inc.add('overflow@x.example', any_scope.call, any)
            ensure
              Triauth::Helpers.define_singleton_method(:sha256, real_digest)
            end
            assert_equal 0, digests, 'the over-cap record must be skipped before its tag is hashed'
            assert_equal Triauth::LIMITS[:maxIncludes], inc.includes.length, 'accepted grants stay usable'
          end
        end
      end

      describe 'Triauth.IdentityIncludes.list' do
        it 'returns the include statements ordered by tag, whatever the publication order' do
          inc = Triauth::IdentityIncludes.new
          inc.add('c@x.example', any_scope.call, any)
          inc.add('a@x.example', any_scope.call({ use: 'sign' }), any)
          inc.add('b._at.x.example', any_scope.call, any)

          listed = inc.list
          assert_equal 3, listed.length
          assert_equal(listed.map { |i| i[:tag] }.sort, listed.map { |i| i[:tag] })
          assert_equal ['a@x.example', 'b._at.x.example', 'c@x.example'], listed.map { |i| i[:ref] }.sort
        end

        it 'returns an empty array when the identity publishes no grants' do
          assert_equal [], Triauth::IdentityIncludes.new.list
        end

        it 'returns a copy - reordering it leaves the canonical order intact' do
          inc = Triauth::IdentityIncludes.new
          inc.add('a@x.example', any_scope.call, any)
          inc.add('b@x.example', any_scope.call, any)

          canonical = inc.list.map { |i| i[:tag] }
          inc.list.reverse!
          assert_equal(canonical, inc.list.map { |i| i[:tag] })
        end
      end

      describe 'Triauth.IdentityIncludes.find' do
        granted_inc = lambda do |use = nil|
          inc = Triauth::IdentityIncludes.new
          inc.add('actor@actor.example', any_scope.call(use.nil? || use.empty? ? {} : { use: use }), any) # `use ?`: string truthiness
          inc
        end
        actor_identity = -> { Triauth::Identity.new('actor@actor.example', {}, { resolver: actor_resolver.call }) }

        it 'returns the matching include statement for a granted mode' do
          inc = granted_inc.call('sign')
          match = inc.find(actor_identity.call, nil, 'sign')
          assert_equal 'actor@actor.example', match&.[](:ref)
        end

        it 'returns null when the mode is not granted, and skips the use check for a null mode (liveness)' do
          inc = granted_inc.call('sign')
          assert_nil inc.find(actor_identity.call, nil, 'auth')
          refute_nil inc.find(actor_identity.call, nil, nil)
        end

        it 'pins the grant when includeTag is given: matching tag found, unknown tag null' do
          inc = granted_inc.call('sign')
          tag = inc.includes[0][:tag]
          refute_nil inc.find(actor_identity.call, tag, 'sign')
          assert_nil inc.find(actor_identity.call, 'A' * 43, 'sign')
        end

        it 'selects deterministically among multiple covering grants: the lexicographically least tag wins, whatever the add order' do
          grants = [{ use: 'sign' }, { use: 'sign,stamp' }, {}].map { |options| any_scope.call(options) }
          tag_of = lambda do |ordering|
            inc = Triauth::IdentityIncludes.new
            ordering.each { |options| assert_equal true, inc.add('actor@actor.example', options, any) }
            inc.find(actor_identity.call, nil, 'sign')[:tag]
          end

          picked = tag_of.call(grants)
          assert_equal tag_of.call(grants.reverse), picked

          inc = Triauth::IdentityIncludes.new
          grants.each { |options| inc.add('actor@actor.example', options, any) }
          assert_equal inc.includes.map { |i| i[:tag] }.min, picked # `sort()[0]`: the least tag
        end

        it 'returns false when the actor identity cannot be resolved (distinct from a revoked grant)' do
          inc = Triauth::IdentityIncludes.new
          inc.add('ghost@dead.example', any_scope.call, any)
          ghost = Triauth::Identity.new('ghost@dead.example', {}, { resolver: DnsResolverStub.new({}) })
          assert_equal false, inc.find(ghost, nil, 'auth')
        end

        it 'gates on the service host: a scoped grant matches its listed hosts exactly, and a null host skips the check (liveness)' do
          inc = Triauth::IdentityIncludes.new
          inc.add('actor@actor.example', { scope: 'svc.example,alt.example' }, any)
          refute_nil inc.find(actor_identity.call, nil, 'auth', 'svc.example')
          refute_nil inc.find(actor_identity.call, nil, 'auth', 'alt.example')
          assert_nil inc.find(actor_identity.call, nil, 'auth', 'sub.svc.example'), 'subdomains do not inherit'
          assert_nil inc.find(actor_identity.call, nil, 'auth', 'other.example')
          refute_nil inc.find(actor_identity.call, nil, 'auth', nil)
          refute_nil inc.find(actor_identity.call, nil, 'auth')
        end

        it 'a scope=any grant covers every service host' do
          inc = granted_inc.call('sign')
          refute_nil inc.find(actor_identity.call, nil, 'sign', 'anywhere.example')
          refute_nil inc.find(actor_identity.call, nil, 'sign', '10.0.0.5')
        end

        it 'scope filters the covering set before the deterministic least-tag pick' do
          mk = lambda do |ordering|
            inc = Triauth::IdentityIncludes.new
            ordering.each { |options| assert_equal true, inc.add('actor@actor.example', options, any) }
            inc
          end
          grants = [{ scope: 'svc.example' }, { scope: 'any' }]
          inc_a = mk.call(grants)
          inc_b = mk.call(grants.reverse)

          # At a host both grants cover, the least tag wins, whatever the add order
          at_svc_a = inc_a.find(actor_identity.call, nil, 'auth', 'svc.example')
          at_svc_b = inc_b.find(actor_identity.call, nil, 'auth', 'svc.example')
          assert_equal at_svc_b[:tag], at_svc_a[:tag]
          assert_equal inc_a.includes.map { |i| i[:tag] }.min, at_svc_a[:tag] # `sort()[0]`: the least tag

          # At a host outside the scoped grant's list, only the scope=any grant covers
          at_other = inc_a.find(actor_identity.call, nil, 'auth', 'other.example')
          assert_equal 'any', at_other[:options][:scope]
        end
      end
    end
  end
end

TestInternals.identity_includes if __FILE__ == $PROGRAM_NAME
