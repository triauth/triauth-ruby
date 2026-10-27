# frozen_string_literal: true

require_relative '../setup'
require_relative '../stubs/dns_resolver'

module TestInternals
  def self.authentication_endpoint
    describe 'Triauth.AuthenticationEndpoint' do
      it 'returns false and sets host to null when multiple triauth records are published' do
        stub = DnsResolverStub.new(
          { 'multi.example.com': { TXT: ['triauth auth1.example.com mode=public', 'triauth auth2.example.com mode=public'] } }
        )
        ae = Triauth::AuthenticationEndpoint.new('multi.example.com', { resolver: stub })
        result = ae.resolve
        assert_equal false, result
        assert_nil ae.host
        assert_nil ae.secure
      end

      it 'SECURITY: refuses to choose among multiple triauth records even when only one of them carries a mode' do
        stub = DnsResolverStub.new(
          { 'multi.example.com': { TXT: ['triauth auth1.example.com', 'triauth auth2.example.com mode=public'] } }
        )
        ae = Triauth::AuthenticationEndpoint.new('multi.example.com', { resolver: stub })
        assert_equal false, ae.resolve
        assert_nil ae.host
      end

      it 'fills the defaults into the options - mode=private and include=any - so they report what the verifier uses' do
        stub = DnsResolverStub.new(
          { 'example.com': { TXT: [{ value: 'triauth auth.example.com', ttl: 1800, dnssec: true }] } }
        )
        ae = Triauth::AuthenticationEndpoint.new('example.com', { resolver: stub })
        assert_equal true, ae.resolve
        assert_equal 'auth.example.com', ae.host
        # options is a plain Hash here (a null-prototype object in JS, compared through a copy there); Hash equality is order-free, as deepStrictEqual is
        assert_equal({ mode: 'private', include: 'any' }, ae.options)
        assert_equal true, ae.secure
      end

      it 'keeps a published include policy and fills only the absent defaults' do
        stub = DnsResolverStub.new(
          { 'example.com': { TXT: ['triauth auth.example.com include=local'] } }
        )
        ae = Triauth::AuthenticationEndpoint.new('example.com', { resolver: stub })
        assert_equal true, ae.resolve
        assert_equal({ include: 'local', mode: 'private' }, ae.options)
      end

      it 'keeps mode, include and the x- extensions, and ignores every other option of the record' do
        stub = DnsResolverStub.new(
          { 'example.com': { TXT: ['triauth auth.example.com mode=public color=blue x-color=blue hasOwnProperty=1 toString=x __proto__=evil'] } }
        )
        ae = Triauth::AuthenticationEndpoint.new('example.com', { resolver: stub })
        assert_equal true, ae.resolve
        # `Object.getPrototypeOf(ae.options) === null` has no counterpart: a Hash has no prototype
        assert_equal({ mode: 'public', include: 'any', 'x-color': 'blue' }, ae.options)
      end

      it 'resolves under any mode value and reports it verbatim - the vocabulary is enforced at identity-domain derivation, not here' do
        ['banana', 'Public', 'PRIVATE', 'public,private'].each do |mode|
          stub = DnsResolverStub.new(
            { 'example.com': { TXT: ["triauth auth.example.com mode=#{mode}"] } }
          )
          ae = Triauth::AuthenticationEndpoint.new('example.com', { resolver: stub })
          assert_equal true, ae.resolve, "mode=#{mode}"
          assert_equal 'auth.example.com', ae.host, "mode=#{mode}"
          assert_equal mode, ae.options[:mode], "mode=#{mode}"
        end
      end

      it 'resolves under each registered mode and exposes it in options' do
        %w[public private].each do |mode|
          stub = DnsResolverStub.new(
            { 'example.com': { TXT: ["triauth auth.example.com mode=#{mode}"] } }
          )
          ae = Triauth::AuthenticationEndpoint.new('example.com', { resolver: stub })
          assert_equal true, ae.resolve, "mode=#{mode}"
          assert_equal 'auth.example.com', ae.host
          assert_equal mode, ae.options[:mode]
        end
      end

      it 'sets secure:true when the triauth record was DNSSEC validated' do
        stub = DnsResolverStub.new(
          { 'example.com': { TXT: [{ value: 'triauth auth.example.com mode=public', ttl: 1800, dnssec: true }] } }
        )
        ae = Triauth::AuthenticationEndpoint.new('example.com', { resolver: stub })
        assert_equal true, ae.resolve
        assert_equal 'auth.example.com', ae.host
        assert_equal true, ae.secure
      end

      it 'records the triauth record\'s expiry from its TTL, and none without a TTL' do
        with_ttl = Triauth::AuthenticationEndpoint.new('example.com', { resolver: DnsResolverStub.new(
          { 'example.com': { TXT: [{ value: 'triauth auth.example.com mode=public', ttl: 60, dnssec: true }] } }
        ) })
        before = Triauth::Helpers.date_now
        assert_equal true, with_ttl.resolve
        assert with_ttl.expires.between?(before + 60_000, Triauth::Helpers.date_now + 60_000), 'expires is the resolution time plus the TTL'

        without_ttl = Triauth::AuthenticationEndpoint.new('example.com', { resolver: DnsResolverStub.new(
          { 'example.com': { TXT: [{ value: 'triauth auth.example.com mode=public', dnssec: true }] } }
        ) })
        assert_equal true, without_ttl.resolve
        assert_nil without_ttl.expires
      end

      it 'urlFor builds the redirect from the bare host' do
        stub = DnsResolverStub.new(
          { 'example.com': { TXT: ['triauth Auth.Example.COM mode=public'] } }
        )
        ae = Triauth::AuthenticationEndpoint.new('example.com', { resolver: stub })
        assert_equal true, ae.resolve
        assert_equal 'auth.example.com', ae.host # lowercased for use

        assert_equal 'https://auth.example.com/', ae.url_for(nil) # the bare endpoint URL
        assert_equal 'https://auth.example.com/auth.html#?challenge=abc-123_XYZ', ae.url_for('auth', { challenge: 'abc-123_XYZ' })
        assert_equal 'https://auth.example.com/sign.html#?challenge=abc&hmac=def', ae.url_for('sign', { challenge: 'abc', hmac: 'def' })
      end

      it 'sets secure:false when the triauth record was not DNSSEC validated' do
        [false, nil].each do |dnssec|
          stub = DnsResolverStub.new(
            { 'example.com': { TXT: [{ value: 'triauth auth.example.com mode=public', ttl: 1800, dnssec: dnssec }] } }
          )
          ae = Triauth::AuthenticationEndpoint.new('example.com', { resolver: stub })
          assert_equal true, ae.resolve
          assert_equal false, ae.secure, "dnssec:#{dnssec.inspect} must map to secure:false"
        end
      end
    end
  end
end

TestInternals.authentication_endpoint if __FILE__ == $PROGRAM_NAME
