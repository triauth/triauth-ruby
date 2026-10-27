# frozen_string_literal: true

require_relative '../setup'
require_relative '../stubs/dns_resolver'
require_relative '../stubs/zone_resolver'
require_relative '../stubs/authenticator'
require 'json'

# Port-only tests: the byte identity of a built challenge with the auth.json suite, the number model of a re-hydrated
# one, and the stage shapes of `Triauth::ChallengeResponseFlow` and `Triauth::Response` decided before any envelope is
# parsed. This file has no triauth-js counterpart (the flow is covered by the API suites there).
module TestInternals
  def self.challenge_response_flow
    describe 'Triauth.Challenge (port-only)' do
      suite = JSON.parse(File.read(File.expand_path('../fixtures/json/auth.json', __dir__)), symbolize_names: true)
      # the first stage-1 case recorded with a deterministic byte stream
      json_case = suite[:tests].find { |t| t.key?(:random) && t[:expected].is_a?(Hash) && t[:expected].key?(:challenge) }
      args = json_case[:args][0]
      expected = json_case[:expected]
      # the runner masks a stage-1 result (test_json.rb): `"ek":"EK"` inside the challenge and `.DK` after it; the
      # public part is the stored challenge before its `.`
      public_challenge = AuthenticatorStub.public_challenge(expected[:challenge])

      it 'builds the auth.json stage-1 challenge byte for byte from a frozen clock and the fixture byte stream' do
        # the case's bytes, handed out in order and never reused (the runner's randomSource contract: a callable returning `n` bytes)
        stream = [json_case[:random]].pack('H*')
        offset = 0
        source = lambda do |n|
          raise 'random bytes exhausted' if offset + n > stream.bytesize

          bytes = stream.byteslice(offset, n)
          offset += n
          bytes
        end

        saved = Triauth::Helpers.method(:date_now)
        begin
          current_time = suite[:currentTime]
          Triauth::Helpers.define_singleton_method(:date_now) { current_time }

          challenge = Triauth::Challenge.build('auth', Triauth::Identity.new(args[:identifier]), { cburl: args[:callbackUrl] }, { randomSource: source })
          # stage 1 sets `ek` right after `build` and before any per-flow member; the fixture carries the masked key
          challenge.data[:ek] = 'EK'

          assert_equal 'DK', expected[:challenge].split('.', -1)[1]
          assert_equal public_challenge, challenge.to_s
          assert_nil challenge.challenge_string
          # the data keys first, then the fixed fields in triauth-js order, then the key stage 1 adds
          assert_equal %i[cburl type identifier nonce iat ver ek], challenge.data.keys
          assert_equal 19, offset # ceil(24 * 0.75) + 1 bytes drawn for the nonce
        ensure
          Triauth::Helpers.define_singleton_method(:date_now, saved)
        end
      end

      it 'round-trips through from_string with an Integer iat and ver (the number model)' do
        challenge = Triauth::Challenge.from_string(public_challenge)

        assert_kind_of Integer, challenge.data[:iat]
        assert_equal suite[:currentTime], challenge.data[:iat]
        assert_equal 1, challenge.data[:ver]
        assert_equal 'auth', challenge.data[:type]
        assert_equal args[:callbackUrl], challenge.data[:cburl]
        assert_equal 'EK', challenge.data[:ek]
        assert_equal args[:identifier], challenge.identity.identifier
        assert_equal public_challenge, challenge.challenge_string
        assert_equal public_challenge, challenge.to_s
      end

      it 'from_string raises on a malformed challenge (base64url, UTF-8 and JSON failures alike)' do
        assert_raises(StandardError) { Triauth::Challenge.from_string('A') } # an impossible base64url length
        assert_raises(StandardError) { Triauth::Challenge.from_string('6Q') } # the lone byte 0xE9: ill-formed UTF-8
        assert_raises(StandardError) { Triauth::Challenge.from_string(Triauth::Helpers.string_to_base64url('[]')) } # the JSON root is not an object
        assert_raises(StandardError) { Triauth::Challenge.from_string(Triauth::Helpers.string_to_base64url('{"iat":1}')) } # no identifier
        # a well-formed document whose identifier is malformed: the Identity constructor's validation error
        err = assert_raises(Triauth::Error) { Triauth::Challenge.from_string(Triauth::Helpers.string_to_base64url('{"identifier":"john"}')) }
        assert_equal 'invalid_identifier', err.code
        assert_equal 'invalid_format', err.reason
      end
    end

    describe 'Triauth.ChallengeResponseFlow (port-only)' do
      # the effective config, as the API methods pass it: the global config merged with the fixture zone resolver
      config = Triauth::Helpers.merge_config({ resolver: TestStubs::ZONE_RESOLVER })
      callbacks = { onChallenge: ->(_) {}, onResponse: ->(_) {} }
      perform = ->(type, options, cbs = callbacks, cfg = config) { Triauth::ChallengeResponseFlow.perform(type, options, cbs, cfg) }
      # the session key of a sign-in, as the flows that follow it receive it
      session_key = AuthenticatorStub::SESSION_KEY

      it 'stage 1 returns {challenge, redirectUrl} for a configured identifier and domain_not_configured for an unconfigured domain' do
        result = perform.call('auth', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb' })

        assert_kind_of Hash, result
        assert_equal %i[challenge redirectUrl], result.keys
        # the stored challenge is `<challenge>.<decryptionKey>`: the public challenge and a 43-character key, nothing after them
        challenge, decryption_key, rest = result[:challenge].split('.', -1)
        assert_nil rest
        assert Triauth::Helpers.is_base64url_string(challenge)
        assert Triauth::Helpers.is_base64url_string(decryption_key)
        assert_equal 43, decryption_key.length
        assert_equal "https://auth.triauthdemo.org/auth.html#?challenge=#{challenge}", result[:redirectUrl]
        # the challenge carries the callback URL, the identifier and an 87-character `ek` (set right after `build`,
        # before any per-flow member), and re-hydrates
        data = Triauth::Challenge.from_string(challenge).data
        assert_equal %i[cburl type identifier nonce iat ver ek], data.keys
        assert_equal 'auth', data[:type]
        assert_equal 'https://example.com/cb', data[:cburl]
        assert_equal 'john@triauthdemo.org', data[:identifier]
        assert_equal 24, data[:nonce].length
        assert Triauth::Helpers.is_base64url_string(data[:ek])
        assert_equal 87, data[:ek].length
        # the key pair works: a probe sealed to `ek` opens with the decryption key
        probe = Triauth::ResponseCipher.seal(data[:ek], 'probe')[:sealedResponse]
        assert_equal 'probe', Triauth::ResponseCipher.open(data[:ek], decryption_key, probe)[:response]

        # the fixture zone has no `triauth` record for example.com
        assert_equal({ error: { code: 'domain_not_configured', message: 'Domain is not configured for triauth' } }, perform.call('auth', { identifier: 'john@example.com', callbackUrl: 'https://example.com/cb' }))

        # a flow that follows a sign-in redirects with the challenge sealed under the session key, next to the key's
        # skid, and never with a readable challenge
        result = perform.call('ping', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb', sessionKey: session_key })
        challenge = AuthenticatorStub.public_challenge(result[:challenge])
        md = %r{\Ahttps://auth\.triauthdemo\.org/ping\.html#\?skid=([A-Za-z0-9_-]{22})&request=([A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,})\z}.match(result[:redirectUrl])
        refute_nil md, result.inspect
        refute_includes result[:redirectUrl], 'challenge='
        assert_equal Triauth::RequestCipher.skid(session_key), md[1]
        assert_equal challenge, Triauth::RequestCipher.open(session_key, md[2])
        assert_equal 'ping', Triauth::Challenge.from_string(challenge).data[:type]

        # a delegated session key `<domain>:<key>` sends the request to the authenticator of that domain, which opens
        # under the key part alone (the fixture zone has no such domain: a per-call stub carries it and the subject's domain)
        resolver = DnsResolverStub.new({ 'issuer.example': { TXT: ['triauth auth.issuer.example mode=public'] }, 'triauthdemo.org': TestStubs::DNS_RECORDS[:'triauthdemo.org'] })
        delegated = Triauth::Helpers.merge_config({ resolver: resolver })
        result = perform.call('ping', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb', sessionKey: "issuer.example:#{session_key}" }, callbacks, delegated)
        md = %r{\Ahttps://auth\.issuer\.example/ping\.html#\?skid=([A-Za-z0-9_-]{22})&request=([A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,})\z}.match(result[:redirectUrl])
        refute_nil md, result.inspect
        assert_equal Triauth::RequestCipher.skid(session_key), md[1]
        assert_equal AuthenticatorStub.public_challenge(result[:challenge]), Triauth::RequestCipher.open(session_key, md[2])
        # a delegated key whose domain is not configured is domain_not_configured, whatever the subject's domain publishes
        assert_equal({ error: { code: 'domain_not_configured', message: 'Domain is not configured for triauth' } }, perform.call('ping', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb', sessionKey: "unconfigured.example:#{session_key}" }, callbacks, delegated))
      end

      it 'rejects an unknown option with invalid_arguments, an unknown config key with invalid_config, a sessionKey on auth with invalid_arguments, a missing sessionKey on ping with invalid_session_key, and a malformed sessionKey with invalid_session_key' do
        assert_equal({ error: { code: 'invalid_arguments', message: 'Unrecognized function argument' } }, perform.call('auth', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb', bogus: 1 }))
        assert_equal({ error: { code: 'invalid_config', message: 'Unrecognized configuration key' } }, perform.call('auth', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb' }, callbacks, config.merge({ bogus: 1 })))
        assert_equal({ error: { code: 'invalid_arguments', message: 'Unrecognized function argument' } }, perform.call('auth', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb', sessionKey: session_key }))
        assert_equal({ error: { code: 'invalid_session_key', reason: 'invalid', message: 'Invalid session key' } }, perform.call('ping', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb' }))
        # a malformed session key is invalid_session_key too: 42 characters, a non-canonical last character, an uppercase or an empty
        # domain, a third part, a non-string, the empty string
        [session_key[0, 42], "#{session_key[0, 42]}9", "Issuer.Example:#{session_key}", ":#{session_key}", "a.example:b.example:#{session_key}", 123, ''].each do |bad|
          assert_equal({ error: { code: 'invalid_session_key', reason: 'invalid', message: 'Invalid session key' } }, perform.call('ping', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb', sessionKey: bad }), bad.inspect)
        end
        # neither stage: invalid_arguments
        assert_equal 'invalid_arguments', perform.call('auth', { identifier: 'john@triauthdemo.org' })[:error][:code]
        assert_equal 'invalid_arguments', perform.call('auth', {})[:error][:code]
      end

      it 'stage 3 maps the callback outcomes: a Hash is returned, nil is request_expired, false is verification_failed, and the literal response false is request_denied' do
        challenge = perform.call('auth', { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/cb' })[:challenge]
        public_challenge, decryption_key = challenge.split('.', -1)
        # the response travels sealed to the challenge's `ek`, as the authenticator sends it
        response = AuthenticatorStub.seal(challenge, '|auth;a;b|')
        outcomes = [{ ok: true, secure: true }, nil, false]
        seen = []
        cbs = {
          onChallenge: ->(_) {},
          onResponse: lambda do |args|
            seen.push(args)
            outcomes.shift
          end
        }

        # onResponse is called with the re-hydrated challenge, the opened response and the session key of the response,
        # before any envelope parsing
        assert_equal({ ok: true, secure: true }, perform.call('auth', { challenge: challenge, response: response }, cbs))
        assert_equal({ error: { code: 'request_expired', message: 'Authentication request has expired, please try again' } }, perform.call('auth', { challenge: challenge, response: response }, cbs))
        assert_equal({ error: { code: 'verification_failed', message: 'Your identity could not be verified' } }, perform.call('auth', { challenge: challenge, response: response }, cbs))
        assert_equal 3, seen.length
        assert_equal %i[challenge response sessionKey], seen[0].keys
        assert_kind_of Triauth::Challenge, seen[0][:challenge]
        assert_equal public_challenge, seen[0][:challenge].challenge_string
        assert_kind_of Triauth::Response, seen[0][:response]
        assert_equal '|auth;a;b|', seen[0][:response].response_string
        # the session key of the opened response: 43 base64url characters, the same for every opening of the same sealed response
        assert Triauth::Helpers.is_base64url_string(seen[0][:sessionKey])
        assert_equal 43, seen[0][:sessionKey].length
        assert_equal seen[0][:sessionKey], seen[2][:sessionKey]
        assert_equal seen[0][:sessionKey], Triauth::ResponseCipher.open(Triauth::Challenge.from_string(public_challenge).data[:ek], decryption_key, response)[:sessionKey]

        # the literal 'false' response is a denial, decided before validation
        assert_equal({ error: { code: 'request_denied', message: 'Request has been denied' } }, perform.call('auth', { challenge: challenge, response: 'false' }, cbs))
        assert_equal 3, seen.length

        # the challenge must match the flow type and the optional identifier / callbackUrl constraints: verification_failed before the callback runs
        assert_equal 'verification_failed', perform.call('ping', { challenge: challenge, response: response }, cbs)[:error][:code]
        assert_equal 'verification_failed', perform.call('auth', { challenge: challenge, response: response, identifier: 'jane@triauthdemo.org' }, cbs)[:error][:code]
        assert_equal 'verification_failed', perform.call('auth', { challenge: challenge, response: response, callbackUrl: 'https://example.com/other' }, cbs)[:error][:code]
        assert_equal 3, seen.length

        # a malformed stored challenge is invalid_challenge: no key, a 42-character key, a third part, a public part that does not
        # re-hydrate, and a challenge whose data has no `ek`
        assert_equal 'invalid_challenge', perform.call('auth', { challenge: public_challenge, response: response }, cbs)[:error][:code]
        assert_equal 'invalid_challenge', perform.call('auth', { challenge: "#{public_challenge}.#{decryption_key[0, 42]}", response: response }, cbs)[:error][:code]
        assert_equal 'invalid_challenge', perform.call('auth', { challenge: "#{challenge}.", response: response }, cbs)[:error][:code]
        assert_equal 'invalid_challenge', perform.call('auth', { challenge: 'A', response: response }, cbs)[:error][:code]
        assert_equal 'invalid_challenge', perform.call('auth', { challenge: "#{Triauth::Helpers.string_to_base64url('[]')}.#{decryption_key}", response: response }, cbs)[:error][:code]
        no_ek = AuthenticatorStub.reencode(challenge, Triauth::Challenge.from_string(public_challenge).data.except(:ek))
        assert_equal 'invalid_challenge', perform.call('auth', { challenge: no_ek, response: response }, cbs)[:error][:code]
        # a malformed response is invalid_response: a plain envelope for a keyed challenge, a tampered ciphertext, a response sealed
        # to another key pair, an opened non-envelope, and a non-response
        assert_equal 'invalid_response', perform.call('auth', { challenge: challenge, response: '|auth;a;b|' }, cbs)[:error][:code]
        enc, ct = response.split('.', -1)
        tampered = "#{enc}.#{ct[0] == 'A' ? 'B' : 'A'}#{ct[1..]}"
        assert_equal 'invalid_response', perform.call('auth', { challenge: challenge, response: tampered }, cbs)[:error][:code]
        other = AuthenticatorStub.store(Triauth::Challenge.from_string(public_challenge).data)
        assert_equal 'invalid_response', perform.call('auth', { challenge: challenge, response: AuthenticatorStub.seal(other, '|auth;a;b|') }, cbs)[:error][:code]
        assert_equal 'invalid_response', perform.call('auth', { challenge: challenge, response: AuthenticatorStub.seal(challenge, 'xx') }, cbs)[:error][:code]
        assert_equal 'invalid_response', perform.call('auth', { challenge: challenge, response: 'xx' }, cbs)[:error][:code]
        assert_equal 3, seen.length

        # requireSecure applies to the callback's result: `secure` first, then `verificationResult.secure`
        strict = config.merge({ requireSecure: true })
        outcomes.push({ ok: true, secure: false }, { ok: true, verificationResult: { secure: true } }, { ok: true, verificationResult: { secure: false } })
        assert_equal 'dnssec_required', perform.call('auth', { challenge: challenge, response: response }, cbs, strict)[:error][:code]
        assert_equal({ ok: true, verificationResult: { secure: true } }, perform.call('auth', { challenge: challenge, response: response }, cbs, strict))
        assert_equal 'dnssec_required', perform.call('auth', { challenge: challenge, response: response }, cbs, strict)[:error][:code]
      end

      it 'assert_secure enforces requireSecure under the JS truthiness of the option' do
        err = assert_raises(Triauth::Error) { Triauth::ChallengeResponseFlow.assert_secure(false, { requireSecure: true }) }
        assert_equal 'dnssec_required', err.code
        assert_equal 'Your domain does not support DNSSEC, which is required to continue.', err.message
        assert_nil Triauth::ChallengeResponseFlow.assert_secure(true, { requireSecure: true })
        # `secure !== true`: nil is rejected like false
        assert_equal 'dnssec_required', assert_raises(Triauth::Error) { Triauth::ChallengeResponseFlow.assert_secure(nil, { requireSecure: true }) }.code

        # the JS falsy set of the option: nil, false, 0 and '' do not enforce
        [nil, false, 0, ''].each do |off|
          assert_nil Triauth::ChallengeResponseFlow.assert_secure(false, { requireSecure: off }), off.inspect
        end
        # anything else is truthy, as in JS
        ['yes', 1, [], {}].each do |on|
          assert_equal 'dnssec_required', assert_raises(Triauth::Error) { Triauth::ChallengeResponseFlow.assert_secure(false, { requireSecure: on }) }.code, on.inspect
        end
      end
    end

    describe 'Triauth.Response (port-only)' do
      it 'answers nil for an iat outside the widened window and false for a non-numeric bound (fail closed)' do
        challenge = Triauth::Challenge.new(Triauth::Identity.new('john@triauthdemo.org'), { type: 'auth', iat: 10_000 })
        response = Triauth::Response.new('|x|')

        # the window is widened by maximalAllowedServerClockDrift (5 s)
        assert_nil response.verify('auth', 'p', challenge, { notBefore: 1_000_000 })
        assert_nil response.verify('auth', 'p', challenge, { notAfter: 0 })
        assert_nil response.verify('auth', 'p', challenge, { notBefore: 15_001 })
        assert_nil response.verify('auth', 'p', challenge, { notAfter: 4_999 })
        # a non-numeric iat is outside any window
        assert_nil response.verify('auth', 'p', Triauth::Challenge.new(challenge.identity, { type: 'auth', iat: '10000' }), { notBefore: 0 })

        # fail closed: a non-numeric or NaN bound, an unknown constraint, a mismatched identifier
        assert_equal false, response.verify('auth', 'p', challenge, { notBefore: 'x' })
        assert_equal false, response.verify('auth', 'p', challenge, { notAfter: Float::NAN })
        assert_equal false, response.verify('auth', 'p', challenge, { bogus: 1 })
        assert_equal false, response.verify('auth', 'p', challenge, { identifier: 'other@triauthdemo.org' })

        # inside the widened window the envelope is parsed: this malformed one raises invalid_signature, as in triauth-js
        err = assert_raises(Triauth::Error) { response.verify('auth', 'p', challenge, { notBefore: 15_000, notAfter: 5_000 }) }
        assert_equal 'invalid_signature', err.code
      end
    end
  end
end

TestInternals.challenge_response_flow if __FILE__ == $PROGRAM_NAME
