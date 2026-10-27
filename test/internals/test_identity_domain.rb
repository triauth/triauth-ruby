# frozen_string_literal: true

require_relative '../setup'
require_relative '../stubs/dns_resolver'
require_relative '../stubs/zone_resolver'

module TestInternals
  def self.identity_domain
    describe 'Triauth.IdentityDomain' do
      describe 'Triauth.IdentityDomain.derive' do
        it 'returns null for an unknown mode' do
          result = Triauth::IdentityDomain.derive('john@example.com', { mode: 'future-mode' })
          assert_nil result
        end

        it 'returns null without a mode, lookup code or not - the default mode is applied by Identity before derivation' do
          assert_nil Triauth::IdentityDomain.derive('john@example.com', {})
          assert_nil Triauth::IdentityDomain.derive('john@private.triauthdemo.org', { lookupCode: 'K7QJ3FB9M2WZX0C4' })
        end

        it 'returns the identity domain with no full label in public mode (nothing is derived)' do
          assert_equal(
            { domainName: 'john._at.example.com' },
            Triauth::IdentityDomain.derive('john@example.com', { mode: 'public' })
          )
        end
      end

      describe 'Triauth.IdentityDomain private-mode derivation (known answers)' do
        identifier  = 'john@private.triauthdemo.org'
        lookup_code = 'K7QJ3FB9M2WZX0C4'
        full_label  = '4GIBDU53B3KGFSZUD5KRVUGITFQ2QAN2C55FNXO25S53WGT6CK6A'
        domain_name = '_4GIBDU53B3._at.private.triauthdemo.org'
        commitment  = '3Q7YSpb3MLMRaQ20VZBUfoySyM4vQrHMfIIuAxER3_s'

        it 'derives the full 52-char base32 string: the HMAC-SHA-256 of the identifier, keyed by the lookup code' do
          assert_equal full_label, Triauth::IdentityDomain.derive_full_label(identifier, lookup_code)
          # The derivation is the plain keyed MAC, reproducible with any HMAC implementation
          mac = Triauth::Helpers.hmac_sha256(Triauth::Helpers.string_to_utf8_bytes(lookup_code), Triauth::Helpers.string_to_utf8_bytes(identifier))
          assert_equal full_label, Triauth::Helpers.uint8_array_to_base32(mac)
        end

        it 'derives the identity domain: a leading underscore, the first 10 characters of the full label, and the ._at. marker' do
          assert_equal(
            { domainName: domain_name, fullLabel: full_label },
            Triauth::IdentityDomain.derive(identifier, { mode: 'private', lookupCode: lookup_code })
          )
          assert_equal "_#{full_label[0, 10]}._at.private.triauthdemo.org", domain_name
        end

        it 'keeps the label length fixed - a published len option is an unknown option key, retained and inert' do
          %w[1 3 16 0 banana].each do |len|
            assert_equal(
              domain_name,
              Triauth::IdentityDomain.derive(identifier, { mode: 'private', len: len, lookupCode: lookup_code })[:domainName],
              len
            )
          end
        end

        it 'lands on an unrelated label under every other lookup code - the label carries no trace of the code' do
          other = Triauth::IdentityDomain.derive(identifier, { mode: 'private', lookupCode: 'ZZZZZZZZZZZZZZZZ' })
          assert_equal '_IIBOSRWME5._at.private.triauthdemo.org', other[:domainName]
          refute_equal full_label, other[:fullLabel]
        end

        it 'returns null when the lookup code is missing or malformed (fail closed, never repaired)' do
          # the JS list opens with `undefined`, which nil covers here
          [nil, 42, 'K7QJ3FB9M2WZX0C', 'K7QJ3FB9M2WZX0C44', 'k7qj3fb9m2wzx0c4', 'K7QJ3FB9M2WZX0C-'].each do |lookup_code_value|
            assert_nil(
              Triauth::IdentityDomain.derive(identifier, { mode: 'private', lookupCode: lookup_code_value }),
              lookup_code_value.inspect
            )
          end
        end

        it 'a lookup code is inert under every other mode - only mode=private consumes one' do
          assert_equal(
            { domainName: 'john._at.private.triauthdemo.org' },
            Triauth::IdentityDomain.derive(identifier, { mode: 'public', lookupCode: lookup_code })
          )
          assert_nil(
            Triauth::IdentityDomain.derive(identifier, { mode: 'future-mode', lookupCode: lookup_code })
          )
        end

        it 'resolve() exposes the commitment over the untruncated label' do
          stub = DnsResolverStub.new({ domain_name.to_sym => { TXT: ['name John Doe'] } })
          id = Triauth::IdentityDomain.new(identifier, { resolver: stub })
          assert_equal true, id.set_options({ mode: 'private', lookupCode: lookup_code }).resolve
          assert_equal commitment, id.expected_commitment
          assert_equal commitment, Triauth::Helpers.sha256(full_label)
        end

        it 'resolve() returns false without a mode, even with a lookup code - nothing is derived and nothing is expected' do
          stub = DnsResolverStub.new({ domain_name.to_sym => { TXT: ['name John Doe'] } })
          id = Triauth::IdentityDomain.new(identifier, { resolver: stub })
          assert_equal false, id.set_options({ lookupCode: lookup_code }).resolve
          assert_nil id.domain_name
          assert_nil id.expected_commitment
        end

        it 'resolve() leaves the expected binding null outside private mode' do
          stub = DnsResolverStub.new(TestStubs::DNS_RECORDS)
          id = Triauth::IdentityDomain.new('john@triauthdemo.org', { resolver: stub })
          id.set_options({ mode: 'public' }).resolve
          assert_nil id.expected_commitment
        end

        it 'resolve() returns false, without querying DNS, when the lookup code is missing' do
          queried = false
          stub = Object.new
          stub.define_singleton_method(:resolve_config) do |*_|
            queried = true
            []
          end
          id = Triauth::IdentityDomain.new(identifier, { resolver: stub })
          assert_equal false, id.set_options({ mode: 'private' }).resolve
          assert_equal false, id.resolved
          assert_nil id.domain_name
          assert_equal false, queried
        end
      end

      describe 'Triauth.IdentityDomain.resolve' do
        it 'returns false when the derived domain name is null (unknown mode)' do
          stub = DnsResolverStub.new(TestStubs::DNS_RECORDS)
          id = Triauth::IdentityDomain.new('john@example.com', { resolver: stub })
          result = id.set_options({ mode: 'future-mode' }).resolve
          assert_equal false, result
          assert_equal false, id.resolved
        end

        it 'throws when the options were never set - there is no derivation to resolve' do
          id = Triauth::IdentityDomain.new('john@triauthdemo.org', { resolver: DnsResolverStub.new(TestStubs::DNS_RECORDS) })

          err = assert_raises(RuntimeError) { id.resolve }
          assert_match(/options not set/, err.message)
        end
      end

      describe 'Triauth.IdentityDomain.setOptions' do
        it 'returns the instance, so the call chains straight into resolve()' do
          id = Triauth::IdentityDomain.new('john@example.com', { resolver: DnsResolverStub.new(TestStubs::DNS_RECORDS) })

          assert_same id, id.set_options({ mode: 'public' })
          assert_equal({ mode: 'public' }, id.options)
          assert_equal true, id.resolve
        end

        it 'sets the options once - a second call is a caller error, not a re-derivation' do
          id = Triauth::IdentityDomain.new('john@example.com')
          id.set_options({ mode: 'public' })

          # Even the identical derivation is refused: the memoized answer is already spoken for
          err = assert_raises(RuntimeError) { id.set_options({ mode: 'private' }) }
          assert_match(/already set/, err.message)
          err = assert_raises(RuntimeError) { id.set_options({ mode: 'public' }) }
          assert_match(/already set/, err.message)
          assert_equal({ mode: 'public' }, id.options)
        end
      end
    end
  end
end

TestInternals.identity_domain if __FILE__ == $PROGRAM_NAME
