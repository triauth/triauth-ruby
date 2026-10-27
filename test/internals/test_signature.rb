# frozen_string_literal: true

require_relative '../setup'
require_relative '../stubs/signer'
require_relative '../stubs/dns_resolver'
require_relative '../stubs/zone_resolver'
require 'json'

module TestInternals
  def self.signature
    identities = JSON.parse(File.read(File.expand_path('../fixtures/identities.json', __dir__)), symbolize_names: true)
    dns_records = JSON.parse(File.read(File.expand_path('../fixtures/dns_records.json', __dir__)), symbolize_names: true)

    describe 'Triauth.Signature' do
      dns_resolver = DnsResolverStub.new(dns_records)
      identity_fixture = identities[:john]
      via = 'https://example.com/'
      message = 'internal-signature-test'

      # `|; x|` makes `x` local to its block: the JS `const`s below shadow the outer ones of the same name, where a
      # plain assignment inside a Ruby block would reassign the outer local.
      it 'returns a string being a valid signature' do |; identity_fixture| # rubocop:disable Layout/SpaceAroundBlockParameters -- block-local variables only, no parameter: the cop misreads `|; x|`
        identity_fixture = identities[:john]
        signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])
        test_messages = ['Test', '', "\x00 \u0000 \n \r \u{1F4A9} \u202E ' \"", ";\n;;\n"]
        # `const testMetadata = [null, {}]` is never read in the reference; it is not declared here (Lint/UselessAssignment)

        test_messages.each do |message|
          signature = Triauth::Signature.generate(->(payload, _ref = nil) { signer_stub.sign(payload) }, 'auth', identity_fixture[:identifier], '', 'https://example.com/', message)

          assert_kind_of String, signature, 'Signature must be a string'
          assert_equal '|', signature[0], 'Signatures must start with |'
          assert_equal '|', signature[-1], 'Signatures must end with |'

          verify_result = Triauth::Signature.new(signature, { resolver: dns_resolver }).verify(message)

          assert_equal true, verify_result[:valid], 'Verification result should have verified set to true for valid signatures'
        end
      end

      describe 'Triauth.Signature.verify constraint enforcement' do |; identity_fixture, message, via| # rubocop:disable Layout/SpaceAroundBlockParameters -- block-local variables only, no parameter: the cop misreads `|; x|`
        identity_fixture = identities[:john]
        message = 'constraint-test-message'
        via = 'https://example.com/'

        # Helper: build a fresh valid signature object bound to the stub resolver
        build_signature = lambda do
          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])
          sig = Triauth::Signature.generate(
            ->(payload, _ref = nil) { signer_stub.sign(payload) },
            'auth',
            identity_fixture[:identifier], '',
            via,
            message
          )
          return Triauth::Signature.new(sig, { resolver: dns_resolver })
        end

        it 'returns null (not false) when notBefore is past the signature ts (fix #5)' do
          sig_obj = build_signature.call
          ts = sig_obj.ts

          res = sig_obj.verify(message, { notBefore: ts + 1000 })
          assert_nil res, 'notBefore in the future of ts must return null so callers can surface "expired"'
        end

        it 'returns null (not false) when notAfter is before the signature ts (fix #5)' do
          sig_obj = build_signature.call
          ts = sig_obj.ts

          res = sig_obj.verify(message, { notAfter: ts - 1000 })
          assert_nil res, 'notAfter in the past of ts must return null so callers can surface "expired"'
        end

        it 'fails closed (returns false) when notBefore is non-numeric (fix #6)' do
          sig_obj = build_signature.call

          res = sig_obj.verify(message, { notBefore: 'not-a-number' })
          assert_equal false, res, 'non-numeric notBefore must fail closed, not silently disable the check'
        end

        it 'fails closed (returns false) when notAfter is NaN (fix #6)' do
          sig_obj = build_signature.call

          res = sig_obj.verify(message, { notAfter: Float::NAN })
          assert_equal false, res, 'NaN notAfter must fail closed, not silently disable the check'
        end

        it 'returns false on type constraint mismatch' do
          sig_obj = build_signature.call

          res = sig_obj.verify(message, { type: 'sign' })
          assert_equal false, res
        end

        it 'returns false on identifier constraint mismatch' do
          sig_obj = build_signature.call

          res = sig_obj.verify(message, { identifier: 'other-user@triauthdemo.org' })
          assert_equal false, res
        end

        it 'returns false on via constraint mismatch' do
          sig_obj = build_signature.call

          res = sig_obj.verify(message, { via: 'https://other-domain.com/' })
          assert_equal false, res
        end

        it "enforces the actor constraint in both directions ('' = require self-signed)" do
          self_signed = build_signature.call
          assert_equal false, self_signed.verify(message, { actor: 'delegate@example.com' }),
                       'requiring a delegate must reject a self-signed signature'

          res = build_signature.call.verify(message, { actor: '' })
          assert_equal true, res[:valid], "actor:'' must accept a self-signed signature"
          assert_equal '', res[:actor]

          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])
          delegated = Triauth::Signature.generate(
            ->(payload, _ref = nil) { signer_stub.sign(payload) }, 'auth', identity_fixture[:identifier], 'delegate@example.com', via, message
          )
          delegated_obj = Triauth::Signature.new(delegated, { resolver: dns_resolver })
          assert_equal false, delegated_obj.verify(message, { actor: '' }),
                       'requiring self-signed must reject a delegated signature'
        end

        it 'returns false on an unrecognized constraint key' do
          sig_obj = build_signature.call

          res = sig_obj.verify(message, { unknownConstraint: 'foo' })
          assert_equal false, res, 'unrecognized constraint keys must surface as a failure, not silently pass'
        end
      end

      describe 'Triauth.Signature.generate' do
        it 'returns false for an unrecognized type' do
          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])
          result = Triauth::Signature.generate(
            ->(p, _ref = nil) { signer_stub.sign(p) }, 'invalid-type', identity_fixture[:identifier], '', via, message
          )
          assert_equal false, result
        end

        it 'returns false when via contains a semicolon - the envelope layer refuses the payload delimiter on its own authority (the URL grammar allows a final-segment ";")' do
          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])
          result = Triauth::Signature.generate(
            ->(p, _ref = nil) { signer_stub.sign(p) }, 'auth', identity_fixture[:identifier], '', 'https://x.com/;evil', message
          )
          assert_equal false, result
        end

        it 'returns false when via contains a pipe (envelope wrapper char) - fails closed instead of emitting a corrupt envelope' do
          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])
          result = Triauth::Signature.generate(
            ->(p, _ref = nil) { signer_stub.sign(p) }, 'auth', identity_fixture[:identifier], '', 'https://x.com/a|b/', message
          )
          assert_equal false, result
        end

        it "accepts only '' or a valid identifier in the actor slot" do
          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])
          generate = lambda do |actor|
            Triauth::Signature.generate(
              ->(p, _ref = nil) { signer_stub.sign(p) }, 'auth', identity_fixture[:identifier], actor, via, message
            )
          end

          # the reference list also carries `undefined`; Ruby has one null, so its `nil` covers both
          [nil, 'Actor@Example.com', 'actor_x@example.com', 'not an identifier'].each do |bad|
            assert_equal false, generate.call(bad), JSON.generate(bad)
          end

          [['', 'self-signed'], ['actor@example.com', 'delegated']].each do |actor, label|
            envelope = generate.call(actor)
            slots = envelope[1...-1].split(';', -1)
            assert_equal 9, slots.length, "#{label}: nine envelope slots"
            assert_equal actor, slots[2], "#{label}: actor slot carries the input verbatim"
          end
        end
      end

      describe 'Triauth.Signature constructor' do
        it 'throws (code invalid_signature) when raw data contains extra pipe delimiters' do
          err = assert_raises(Triauth::Error) { Triauth::Signature.new('|a|b|') }
          assert_equal 'invalid_signature', err.code
        end
      end

      describe 'Triauth.Signature.verify additional branches' do
        it 'returns false when cryptoSignatures is empty (defensive guard)' do
          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])
          sig = Triauth::Signature.generate(
            ->(p, _ref = nil) { signer_stub.sign(p) }, 'auth', identity_fixture[:identifier], '', via, message
          )
          sig_obj = Triauth::Signature.new(sig, { resolver: dns_resolver })
          sig_obj.crypto_signatures = []
          result = sig_obj.verify(message)
          assert_equal false, result
        end

        it 'rejects with TriauthError dns_unavailable when DNS resolution throws (propagated, not swallowed into false)' do
          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])
          sig = Triauth::Signature.generate(
            ->(p, _ref = nil) { signer_stub.sign(p) }, 'auth', 'a@dnssec-failed.org', '', via, message
          )
          # No custom resolver: the suite's zone resolver publishes dnssec-failed.org as a resolution
          # failure, exactly as a validating resolver reports it. The rejection must propagate so API
          # methods can surface a retryable {error:dns_unavailable} instead of a false "signature invalid" verdict.
          sig_obj = Triauth::Signature.new(sig)
          err = assert_raises(Triauth::Error) { sig_obj.verify(message) }
          assert_equal 'dns_unavailable', err.code
        end
      end

      describe 'Triauth.MultiSignature.verify constraint enforcement' do
        build_sig = lambda do |device = 0|
          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][device][:keys][0][:private])
          return Triauth::Signature.generate(
            ->(p, _ref = nil) { signer_stub.sign(p) }, 'auth', identity_fixture[:identifier], '', via, message
          )
        end

        it 'returns false when signature count is below minSignatures' do
          sig = build_sig.call
          ms = Triauth::MultiSignature.new(Triauth::MultiSignature.generate(sig), { resolver: dns_resolver })
          assert_equal false, ms.verify(message, { minSignatures: 2 })
        end

        it 'returns false when signature count exceeds maxSignatures' do
          sig1 = build_sig.call
          sig2 = build_sig.call(1)
          ms = Triauth::MultiSignature.new(Triauth::MultiSignature.generate(sig1, sig2), { resolver: dns_resolver })
          assert_equal false, ms.verify(message, { maxSignatures: 1 })
        end

        it 'fails closed (returns false) when a signature-count bound is non-numeric' do
          # The primitive defends itself even though Triauth.verify now rejects non-numeric bounds with invalid_arguments
          # before delegating here; Response.verify (the challenge-response flows) reaches this guard directly.
          sig = build_sig.call
          ms = Triauth::MultiSignature.new(Triauth::MultiSignature.generate(sig), { resolver: dns_resolver })
          assert_equal false, ms.verify(message, { maxSignatures: '1' })
        end

        it 'rejects byte-identical duplicate segments at parse time (invalid_signature), while distinct segments of the same identity parse fine' do
          sig = build_sig.call

          # A single signature replayed to pad the segment count is never legitimate
          err = assert_raises(Triauth::Error) do
            Triauth::MultiSignature.new(Triauth::MultiSignature.generate(sig, sig), { resolver: dns_resolver })
          end
          assert_equal 'invalid_signature', err.code

          # Two signatures by two devices of the same identity differ in bytes on every runtime and parse fine
          sig2 = build_sig.call(1)
          ms = Triauth::MultiSignature.new(Triauth::MultiSignature.generate(sig, sig2), { resolver: dns_resolver })
          assert_equal 2, ms.signatures.length
        end
      end

      # The tests below exist only in the port: they pin the number model and the
      # regex anchors of the envelope parser, the MultiSignature limits and the String result of a crypto signer.

      # An envelope built by hand from its nine slots, joined and wrapped the way `generate` does it.
      envelope_of = ->(slots) { Triauth::Protocol::WRAPPER + slots.join(Triauth::Protocol::DELIMITER) + Triauth::Protocol::WRAPPER }

      describe 'Triauth.Signature (port-only)' do
        it 'parses a 16-digit ts slot through a double as parseInt does: 9007199254740993 reads 9007199254740992 in ts and signedAt, 1777454675000 stays exact' do
          signer_stub = SignerStub.from_jwk(identity_fixture[:devices][0][:keys][0][:private])

          # The crypto signature covers the payload carrying the rounded ts while the envelope carries the 16-digit
          # slot: the envelope verifies only when the slot is read back as the double JS reads (an exact parse fails).
          signed_slots = ['auth', identity_fixture[:identifier], '', via, 'v1', '9007199254740992', '', '', message]
          crypto_signature = signer_stub.sign(signed_slots.join(';'))[0]
          sig_obj = Triauth::Signature.new(envelope_of.call(['auth', identity_fixture[:identifier], '', via, 'v1', '9007199254740993', '', '', crypto_signature]), { resolver: dns_resolver })
          assert_equal 9_007_199_254_740_992, sig_obj.ts
          assert_equal 1, sig_obj.ver
          res = sig_obj.verify(message)
          assert_equal true, res[:valid]
          assert_equal 9_007_199_254_740_992, res[:signedAt]

          # A 13-digit ts (below 2**53) is exact on both sides
          signed_slots = ['auth', identity_fixture[:identifier], '', via, 'v1', '1777454675000', '', '', message]
          crypto_signature = signer_stub.sign(signed_slots.join(';'))[0]
          sig_obj = Triauth::Signature.new(envelope_of.call(signed_slots[0, 8] + [crypto_signature]), { resolver: dns_resolver })
          assert_equal 1_777_454_675_000, sig_obj.ts
          res = sig_obj.verify(message)
          assert_equal true, res[:valid]
          assert_equal 1_777_454_675_000, res[:signedAt]
        end

        it 'refuses a ts or ver slot with a trailing newline and a ts with a leading zero (absolute anchors): invalid_signature' do
          slots = ['auth', identity_fixture[:identifier], '', via, 'v1', '1777454675000', '', '', 'AAAA']
          assert_equal 1_777_454_675_000, Triauth::Signature.new(envelope_of.call(slots)).ts

          [[5, "1777454675000\n"], [4, "v1\n"], [5, '0177']].each do |index, value|
            bad_slots = slots.dup
            bad_slots[index] = value
            err = assert_raises(Triauth::Error) { Triauth::Signature.new(envelope_of.call(bad_slots)) }
            assert_equal 'invalid_signature', err.code, value.inspect
          end
        end

        it 'places a single String returned by the crypto signer verbatim in the signature slot (an Array is joined with ";")' do
          envelope = Triauth::Signature.generate(->(_payload, _ref = nil) { 'c2lnbmF0dXJl' }, 'auth', identity_fixture[:identifier], '', via, message)
          slots = envelope[1...-1].split(';', -1)
          assert_equal 9, slots.length
          assert_equal 'c2lnbmF0dXJl', slots[8]

          envelope = Triauth::Signature.generate(->(_payload, _ref = nil) { %w[AAAA AAAB] }, 'auth', identity_fixture[:identifier], '', via, message)
          assert_equal %w[AAAA AAAB], envelope[1...-1].split(';', -1)[8..]
        end
      end

      describe 'Triauth.MultiSignature (port-only)' do
        it 'refuses an envelope above LIMITS.signatureBytesize and one carrying more than LIMITS.maxMultiSignatures segments: invalid_signature' do
          limit = Triauth::Protocol::LIMITS[:signatureBytesize]

          err = assert_raises(Triauth::Error) { Triauth::MultiSignature.new(Triauth::Protocol::WRAPPER + ('x' * limit) + Triauth::Protocol::WRAPPER) }
          assert_equal 'invalid_signature', err.code

          err = assert_raises(Triauth::Error) { Triauth::MultiSignature.new('|a|b|c|d|e|f|') }
          assert_equal 'invalid_signature', err.code

          # With well-formed segments: five parse and six are refused by the count alone; an envelope of exactly
          # LIMITS.signatureBytesize bytes parses and one byte more is refused.
          envelopes = %w[AAAA AAAB AAAC AAAD AAAE AAAF].map do |crypto_signature|
            envelope_of.call(['auth', identity_fixture[:identifier], '', via, 'v1', '1777454675000', '', '', crypto_signature])
          end
          assert_equal 5, Triauth::MultiSignature.new(Triauth::MultiSignature.generate(*envelopes[0, 5])).signatures.length
          err = assert_raises(Triauth::Error) { Triauth::MultiSignature.new(Triauth::MultiSignature.generate(*envelopes)) }
          assert_equal 'invalid_signature', err.code

          padding = limit - envelopes[0].bytesize
          at_limit = envelope_of.call(['auth', identity_fixture[:identifier], '', via, 'v1', '1777454675000', '', '', "AAAA#{'A' * padding}"])
          assert_equal limit, at_limit.bytesize
          assert_equal 1, Triauth::MultiSignature.new(at_limit).signatures.length
          err = assert_raises(Triauth::Error) { Triauth::MultiSignature.new(envelope_of.call(['auth', identity_fixture[:identifier], '', via, 'v1', '1777454675000', '', '', "AAAA#{'A' * (padding + 1)}"])) }
          assert_equal 'invalid_signature', err.code
        end
      end
    end
  end
end

TestInternals.signature if __FILE__ == $PROGRAM_NAME
