# frozen_string_literal: true

require_relative 'setup'
require_relative 'stubs/signer'
require_relative 'stubs/authenticator'
# The demo zone, served from the fixture: the suites resolve through it, as the triauth-js run does through test_unit.js
require_relative 'stubs/zone_resolver'
require 'json'

# The fixtures: the identities and the attesters with Symbol keys (compared to the port's Symbol-keyed results directly),
# the identifiers with String keys (the keys of `invalidIdentifiers` are identifier values, not property names); all guarded
# so that test.rb and a standalone run load them once (`IDENTITIES` and `IDENTIFIERS_FIXTURE` are shared with the other API suites)
IDENTITIES = JSON.parse(File.read(File.expand_path('fixtures/identities.json', __dir__)), symbolize_names: true) unless defined?(IDENTITIES)
ATTESTERS = JSON.parse(File.read(File.expand_path('fixtures/attesters.json', __dir__)), symbolize_names: true) unless defined?(ATTESTERS)
IDENTIFIERS_FIXTURE = JSON.parse(File.read(File.expand_path('fixtures/identifiers.json', __dir__))) unless defined?(IDENTIFIERS_FIXTURE)

describe 'Attestation API' do
  describe 'Triauth.attest' do
    describe 'accepts identifier, callbackUrl, attestations, and sessionKey to produce challenge and redirectUrl' do
      identifier = 'john@triauthdemo.org'
      callback_url = 'https://example.com/'
      session_key = AuthenticatorStub::SESSION_KEY
      attestations = {
        'not-a-robot': {
          label: 'I am not a robot',
          providers: ['https://triauthdemo.org/not-a-robot']
        }
      }

      it 'returns challenge and a correct redirectUrl for valid input' do
        attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: attestations, sessionKey: session_key })
        assert attest_res[:challenge].is_a?(String) && attest_res[:challenge].length > 0
        assert attest_res[:redirectUrl].is_a?(String) && attest_res[:redirectUrl].length > 0
      end

      it 'encodes type, identifier, callbackUrl, and attestations in the challenge' do
        attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: attestations, sessionKey: session_key })
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(attest_res[:challenge]))

        assert_equal 'attest', challenge_request.data[:type]
        assert_equal identifier, challenge_request.data[:identifier]
        assert_equal callback_url, challenge_request.data[:cburl]
        assert_equal attestations, challenge_request.data[:attest]
      end

      it 'seals the challenge into redirectUrl under the session key, next to its skid' do
        attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: attestations, sessionKey: session_key })
        assert attest_res[:redirectUrl].include?('#?skid=') && attest_res[:redirectUrl].include?('&request=')
        assert !attest_res[:redirectUrl].include?('challenge=') && !attest_res[:redirectUrl].include?('token=')
      end

      it 'rejects a request without a session key with invalid_session_key - attest follows a sign-in' do
        attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: attestations })
        assert_equal 'invalid_session_key', attest_res.dig(:error, :code) # `attestRes?.error?.code`
      end

      it 'returns validation error for invalid identifiers' do
        invalid_identifiers = IDENTIFIERS_FIXTURE['invalidIdentifiers'] # `const {invalidIdentifiers} = identifiersFixture`
        invalid_identifiers.each_key do |invalid_identifier| # `for...in`
          attest_res = Triauth.attest({ identifier: invalid_identifier, callbackUrl: callback_url, attestations: attestations, sessionKey: session_key })
          refute attest_res[:attested], invalid_identifier
          assert_equal 'invalid_identifier', attest_res[:error][:code], invalid_identifier
        end
      end

      it 'returns {error:{code:invalid_callback_url}} for invalid callbackUrls' do
        invalid_urls = ['=', '', "https://[::1]/#{'a' * 1100}"]

        invalid_urls.each do |invalid_url|
          attest_res = Triauth.attest({ identifier: identifier, callbackUrl: invalid_url, attestations: attestations, sessionKey: session_key })
          refute attest_res[:attested]
          assert_equal 'invalid_callback_url', attest_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_arguments}} for unrecognized options' do
        attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: attestations, sessionKey: session_key, unknownKey: 1 })
        refute attest_res[:attested]
        assert_equal 'invalid_arguments', attest_res[:error][:code]
      end

      it 'returns {error:{code:invalid_session_key}} for invalid session keys' do
        invalid_session_keys = ['short', 123, '', 'A' * 42, 'A' * 44, ":#{'a' * 16}", "#{'A' * 42}+", "#{'A' * 42}B",
                                ":#{'A' * 43}", "Issuer.Example:#{'A' * 43}", "not_a_domain:#{'A' * 43}", "a.example:b.example:#{'A' * 43}",
                                "#{'a' * 254}:#{'A' * 43}", ':' * (8 * 1024 * 1024)]
        invalid_session_keys.each do |invalid_session_key|
          attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: attestations, sessionKey: invalid_session_key })
          refute attest_res[:attested]
          assert_equal 'invalid_session_key', attest_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_attestations}} when attestations option is null or non-object' do
        [nil, 'string', 123, []].each do |invalid_attestations|
          attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: invalid_attestations, sessionKey: session_key })
          refute attest_res[:attested]
          assert_equal 'invalid_attestations', attest_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_attestations}} when an entry is null' do
        attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: { 'not-a-robot': nil }, sessionKey: session_key })
        refute attest_res[:attested]
        assert_equal 'invalid_attestations', attest_res[:error][:code]
      end

      it 'returns {error:{code:invalid_attestations}} for attestation IDs outside printable ASCII' do
        # An attestation ID becomes a property name of the challenge, which stage-3 safeParseJson admits only in ASCII
        %w[wiek-ż ロボット].each do |id|
          attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: { id.to_sym => { label: 'lbl', providers: ['https://triauthdemo.org/p'] } }, sessionKey: session_key }) # `{[id]: {...}}`
          refute attest_res[:attested], id
          assert_equal 'invalid_attestations', attest_res[:error][:code], id
        end
      end

      it 'returns {error:{code:invalid_attestations}} when an entry has an unknown property' do
        bad = { 'not-a-robot': { label: 'I am not a robot', providers: ['https://triauthdemo.org/p'], extra: 'x' } }
        attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: bad, sessionKey: session_key })
        refute attest_res[:attested]
        assert_equal 'invalid_attestations', attest_res[:error][:code]
      end

      it 'returns {error:{code:invalid_attestations}} when an entry is missing label or providers' do
        sets = [
          { a: { providers: ['https://triauthdemo.org/p'] } },                          # missing label
          { a: { label: '', providers: ['https://triauthdemo.org/p'] } },               # empty label
          { a: { label: 'lbl' } },                                                       # missing providers
          { a: { label: 'lbl', providers: [] } }                                         # empty providers
        ]
        sets.each do |bad|
          attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: bad, sessionKey: session_key })
          refute attest_res[:attested]
          assert_equal 'invalid_attestations', attest_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_attestations}} when providers list is too long' do
        too_many = (0...Triauth::LIMITS[:maxMultiSignatures]).map { |i| "https://triauthdemo.org/p#{i}" }
        bad = { a: { label: 'lbl', providers: too_many } }
        attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: bad, sessionKey: session_key })
        refute attest_res[:attested]
        assert_equal 'invalid_attestations', attest_res[:error][:code]
      end

      it 'returns {error:{code:invalid_attestations}} for malformed provider URLs' do
        sets = [
          'http://insecure.example/p',
          'https://user:pass@example.com/p',
          'https://example.com/p?q=1',
          'https://example.com/p#frag',
          'https://example.com/p%20space',
          'https://xn--example.com/p'
        ]
        sets.each do |bad_url|
          bad = { a: { label: 'lbl', providers: [bad_url] } }
          attest_res = Triauth.attest({ identifier: identifier, callbackUrl: callback_url, attestations: bad, sessionKey: session_key })
          refute attest_res[:attested], bad_url
          assert_equal 'invalid_attestations', attest_res[:error][:code], bad_url
        end
      end
    end

    describe 'accepts challenge and response to produce attestation result' do
      callback_url = 'https://example.com/'
      attester_via = 'https://triauthdemo.org/not-a-robot'
      attestations = {
        'not-a-robot': {
          label: 'I am not a robot',
          providers: [attester_via]
        }
      }

      # (the destructured options object of the JS arrow function: keyword arguments with the same defaults)
      build_response = lambda do |identity, device, challenge, user_via: callback_url, attester_identifier: identity[:identifier], attester_via_override: attester_via, user_type: 'attest', attester_type: 'attest', attester_signed_metadata: {}, omit_attester: false|
        override_message = Triauth::Helpers.sha256(AuthenticatorStub.public_challenge(challenge))

        user_sig = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          user_type,
          identity[:identifier], '',
          user_via,
          override_message
        )

        if omit_attester
          return Triauth::MultiSignature.generate(user_sig)
        end

        attester_sig = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          attester_type,
          attester_identifier, '',
          attester_via_override,
          override_message,
          attester_signed_metadata
        )

        return Triauth::MultiSignature.generate(user_sig, attester_sig)
      end

      it 'correctly sets the attested status (self-attestation)' do
        IDENTITIES.each_value do |identity|
          # The attester via hostname must equal the attester identifier's domain (see
          # src/api/attestation.js:275), so for self-attestation the via uses the user's domain.
          domain = identity[:identifier].split('@', -1)[1]
          per_identity_via = "https://#{domain}/not-a-robot"
          per_identity_attestations = {
            'not-a-robot': { label: 'I am not a robot', providers: [per_identity_via] }
          }

          build_res = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: per_identity_attestations })
          challenge = build_res[:challenge]

          identity[:devices].each do |device|
            response = build_response.call(identity, device, challenge, attester_via_override: per_identity_via)

            attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })

            assert_equal true, attest_res[:attested]
            assert_equal true, attest_res[:secure]
            assert_equal identity[:identifier], attest_res[:identifier]
            assert_equal identity[:identityDomain], attest_res[:identityDomain]
            assert_equal '', attest_res[:actorIdentityDomain]
            assert_equal '', attest_res[:lookupCode]
            assert_equal '', attest_res[:actorLookupCode]
            assert_equal device[:deviceName], attest_res[:deviceName]
            assert attest_res[:expires] > Triauth::Helpers.date_now
            assert_equal device[:keys].length, attest_res[:keys].length
            assert_equal(true, attest_res[:keys].all? { |k| k[:verified] })

            att = attest_res[:attestations][:'not-a-robot']
            assert_equal true, att[:valid]
            assert_equal 'attest', att[:type]
            assert_equal identity[:identifier], att[:identifier]
            assert_equal per_identity_via, att[:via]

            # Top-level milestone timeline (signedAt = user's mainSig); nested attester carries its own.
            assert attest_res[:signedAt].between?(attest_res[:issuedAt], attest_res[:verifiedAt]) # `issuedAt <= signedAt && signedAt <= verifiedAt` (RuboCop `Style/ComparableBetween`)
            assert Triauth::Helpers.is_number(att[:signedAt]) && Triauth::Helpers.is_number(att[:verifiedAt]) # `typeof === 'number'`
            # top-level verifiedAt is the max across all signatures (user + attesters)
            assert attest_res[:verifiedAt] >= att[:verifiedAt]
          end
        end
      end

      it 'allows one attester signature to satisfy multiple attestation IDs' do
        multi_attestations = {
          first: { label: 'first', providers: [attester_via] },
          second: { label: 'second', providers: [attester_via] }
        }

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: multi_attestations })[:challenge]
        response = build_response.call(identity, device, challenge)

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, attest_res[:attested]
        assert_equal true, attest_res[:attestations][:first][:valid]
        assert_equal true, attest_res[:attestations][:second][:valid]
      end

      it 'accepts attester bind.identifier and bind.via that match the user' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })[:challenge]
        response = build_response.call(identity, device, challenge, attester_signed_metadata: { bind: { identifier: identity[:identifier], via: callback_url } })

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, attest_res[:attested]
      end

      it 'rejects when attester signature is missing entirely' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })[:challenge]
        response = build_response.call(identity, device, challenge, omit_attester: true)

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      it 'rejects when attester `via` is not in the requested providers list' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })[:challenge]
        response = build_response.call(identity, device, challenge, attester_via_override: 'https://triauthdemo.org/some-other-attestation')

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      it "rejects when attester identifier's domain does not match the attester via hostname" do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        # provider list contains a via under example.com but the attester signs with
        # identifier=john@triauthdemo.org → triauthdemo.org !== example.com → check 2 fails.
        custom_attestations = {
          'not-a-robot': {
            label: 'I am not a robot',
            providers: ['https://example.com/not-a-robot']
          }
        }

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: custom_attestations })[:challenge]
        response = build_response.call(identity, device, challenge, attester_via_override: 'https://example.com/not-a-robot')

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      it 'rejects when attester signature is cryptographically invalid' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })[:challenge]
        good_response = build_response.call(identity, device, challenge)

        # Flip a character in the attester segment (after the first '|...|' which is the user sig)
        first_pipe = good_response.index('|', 1)
        second_pipe = good_response.index('|', first_pipe + 1)
        attester_part = good_response[second_pipe..]
        # tamper - replace a base64url character inside the attester segment
        # (JS `slice(0, -10)` of a short string is `''`; a nil interpolates as `''` here; `^`/`$` are `\A`/`\z`)
        tampered_attester = attester_part.sub('A', 'B').sub(/\A([^B]+)\z/, "#{attester_part[0...-10]}AAAAAAAAA#{attester_part[-1]}")
        bad_response = good_response[0...second_pipe] + tampered_attester

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, bad_response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      it 'rejects when attester bind.identifier is present and differs from the user identifier' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })[:challenge]
        response = build_response.call(identity, device, challenge, attester_signed_metadata: { bind: { identifier: 'someone-else@example.com' } })

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      it 'rejects when attester bind.via is present and differs from the user via' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })[:challenge]
        response = build_response.call(identity, device, challenge, attester_signed_metadata: { bind: { via: 'https://wrong.example/' } })

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      it 'rejects challenges whose embedded `type` does not match the attest flow' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        build_res = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:type] = 'auth'
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = build_response.call(identity, device, modified_challenge)

        attest_res = Triauth.attest({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      it 'rejects responses whose envelope `type` is not `attest`' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })[:challenge]
        response = build_response.call(identity, device, challenge, user_type: 'auth')

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      it 'rejects when user signature `via` is not a prefix of challenge `cburl`' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })[:challenge]
        response = build_response.call(identity, device, challenge, user_via: 'https://attacker.example/')

        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      it 'does not attest expired challenges' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        build_res = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:iat] = Triauth::Helpers.date_now - (Triauth.config[:attestTimeout] + 10_000)
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = build_response.call(identity, device, modified_challenge)

        attest_res = Triauth.attest({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute attest_res[:attested]
        assert_equal 'request_expired', attest_res[:error][:code]
      end

      it 'honors per-call attestTimeout override' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        default_timeout = Triauth.config[:attestTimeout]

        build_res = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:iat] = Triauth::Helpers.date_now - (default_timeout + 10_000)
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = build_response.call(identity, device, modified_challenge)

        attest_res = Triauth.attest({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute attest_res[:attested]
        assert_equal 'request_expired', attest_res[:error][:code]

        attest_res = Triauth.attest(
          { challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) },
          { attestTimeout: (default_timeout * 2) + 60_000 }
        )
        assert_equal true, attest_res[:attested]
      end

      it 'rejects when the first signature identifier differs from the challenge identity (identifier mismatch guard)' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        # The user slot is signed by another identity under its own records: the crypto verifies,
        # and only the identifier comparison against the challenge fails
        other = ATTESTERS[:robot]

        challenge = Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, attestations: attestations })[:challenge]
        signed_payload = Triauth::Helpers.sha256(AuthenticatorStub.public_challenge(challenge))

        user_sig = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(other[:devices][0][:keys]),
          'attest',
          other[:identifier], '',
          callback_url,
          signed_payload
        )

        attester_sig = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'attest',
          identity[:identifier], '',
          attester_via,
          signed_payload
        )

        response = Triauth::MultiSignature.generate(user_sig, attester_sig)
        attest_res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute attest_res[:attested]
        assert_equal 'verification_failed', attest_res[:error][:code]
      end

      # The JS version maps every call to a promise whose `.catch(() => assert(false))` swallows the assertion failure inside
      # `Promise.allSettled`, so it passes whatever the library returns (RUN/upstream.md item 5). Here each call runs in turn and
      # its result is asserted; an exception escaping any call fails the test. `void 0` is the key left out, `null` is `nil`.
      it 'does not attest invalid challenges or responses' do
        valid_challenge = 'eyJ0eXBlIjoiYXR0ZXN0IiwiaWRlbnRpZmllciI6ImpvaG5AdHJpYXV0aGRlbW8ub3JnIiwibm9uY2UiOiJ3dHI2SlZYRlVaSkJKVUx0aTNhWVpvNUEiLCJpYXQiOjE3Mzc3MTEwNDU0NjUsInZlciI6MX0'
        valid_response = '|attest;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|'
        invalid_values = [nil, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ']

        r = Triauth.attest({ response: valid_response }) # `challenge: void 0`
        refute r[:attested]
        invalid_values.each do |invalid_challenge|
          r = Triauth.attest({ challenge: invalid_challenge, response: valid_response })
          refute r[:attested]
        end
        r = Triauth.attest({ challenge: valid_challenge }) # `response: void 0`
        refute r[:attested]
        invalid_values.each do |invalid_response|
          r = Triauth.attest({ challenge: valid_challenge, response: invalid_response })
          refute r[:attested]
        end
      end
    end

    describe 'third-party attestation with a distinct attester identity' do
      john = IDENTITIES[:john]
      robot = ATTESTERS[:robot]
      age = ATTESTERS[:age]
      callback_url = 'https://example.com/'
      user_via = 'https://example.com/' # Helpers.getBaseUrl(callbackUrl)

      mk_sig = lambda do |challenge, keys, identifier, via, signed_metadata = {}|
        Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(keys), 'attest', identifier, '', via,
          Triauth::Helpers.sha256(AuthenticatorStub.public_challenge(challenge)), signed_metadata
        )
      end

      user_sig = ->(challenge, via = user_via) { mk_sig.call(challenge, john[:devices][0][:keys], john[:identifier], via) }
      # (`{ via, signedMetadata = {} } = {}`: keyword arguments; `via ?? attester.via` is the nil test)
      attester_sig = ->(challenge, attester, via: nil, signed_metadata: {}) { mk_sig.call(challenge, attester[:devices][0][:keys], attester[:identifier], via.nil? ? attester[:via] : via, signed_metadata) }
      build_challenge = ->(attns) { Triauth.attest({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: john[:identifier], callbackUrl: callback_url, attestations: attns })[:challenge] }

      robot_attestations = { 'not-a-robot': { label: 'I am not a robot', providers: [robot[:via]] } }

      it 'verifies an attester signing under its OWN distinct identifier and identity domain' do
        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(user_sig.call(challenge), attester_sig.call(challenge, robot))

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })

        assert_equal true, res[:attested]
        assert_equal john[:identifier], res[:identifier]

        att = res[:attestations][:'not-a-robot']
        assert_equal true, att[:valid]
        assert_equal 'attest', att[:type]
        assert_equal robot[:identifier], att[:identifier]                  # distinct from the user
        refute_equal john[:identifier], att[:identifier]
        assert_equal robot[:via], att[:via]
        assert_equal robot[:identityDomain], att[:identityDomain]
        assert_equal '', att[:actorIdentityDomain], 'attester statements are first-party'
        assert_equal '', att[:lookupCode]
        assert_equal '', att[:actorLookupCode]
      end

      it 'verifies two DISTINCT attesters satisfying two attestations in one envelope' do
        attns = {
          'not-a-robot': { label: 'I am not a robot', providers: [robot[:via]] },
          'over-18':     { label: 'I am over 18',     providers: [age[:via]] }
        }
        challenge = build_challenge.call(attns)
        response = Triauth::MultiSignature.generate(
          user_sig.call(challenge),
          attester_sig.call(challenge, robot),
          attester_sig.call(challenge, age)
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })

        assert_equal true, res[:attested]
        assert_equal robot[:identifier], res[:attestations][:'not-a-robot'][:identifier]
        assert_equal age[:identifier], res[:attestations][:'over-18'][:identifier]
      end

      it 'accepts a distinct attester whose bind.identifier, bind.via, and bind.deviceTag all bind the user' do
        # Learn the user main-sig deviceTag from a plain attestation (avoids hard-coding it).
        ch0 = build_challenge.call(robot_attestations)
        base = Triauth.attest({ challenge: ch0, response: AuthenticatorStub.seal(ch0, Triauth::MultiSignature.generate(user_sig.call(ch0), attester_sig.call(ch0, robot))) })
        user_tag = base[:deviceTag]

        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(
          user_sig.call(challenge),
          attester_sig.call(challenge, robot, signed_metadata: { bind: { identifier: john[:identifier], via: user_via, deviceTag: user_tag } })
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, res[:attested]
      end

      it 'rejects a distinct attester whose bind.deviceTag does NOT match the user deviceTag' do
        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(
          user_sig.call(challenge),
          attester_sig.call(challenge, robot, signed_metadata: { bind: { deviceTag: 'not-the-users-device-tag' } })
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute res[:attested]
        assert_equal 'verification_failed', res[:error][:code]
      end

      it 'rejects a distinct attester whose bind.identifier is present and differs from the user identifier' do
        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(
          user_sig.call(challenge),
          attester_sig.call(challenge, robot, signed_metadata: { bind: { identifier: 'someone-else@example.com' } })
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute res[:attested]
        assert_equal 'verification_failed', res[:error][:code]
      end

      it 'rejects a distinct attester whose bind.via is present and differs from the user via' do
        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(
          user_sig.call(challenge),
          attester_sig.call(challenge, robot, signed_metadata: { bind: { via: 'https://wrong.example/' } })
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute res[:attested]
        assert_equal 'verification_failed', res[:error][:code]
      end

      it 'SECURITY: rejects a distinct attester carrying an UNRECOGNIZED binder inside bind - every member of bind is critical, so a constraint the verifier cannot enforce fails the bundle instead of going unread' do
        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(
          user_sig.call(challenge),
          attester_sig.call(challenge, robot, signed_metadata: { bind: { audience: 'https://somewhere.example/' } })
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute res[:attested]
        assert_equal 'verification_failed', res[:error][:code]
      end

      it 'SECURITY: rejects a malformed bind (empty, an array, or a non-object) - a bind that states nothing is a producer error, not an anonymous attestation' do
        [{}, 'identifier', ['identifier'], nil].each do |bind|
          challenge = build_challenge.call(robot_attestations)
          response = Triauth::MultiSignature.generate(
            user_sig.call(challenge),
            attester_sig.call(challenge, robot, signed_metadata: { bind: bind })
          )

          res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
          refute res[:attested], JSON.generate(bind)
          assert_equal 'verification_failed', res[:error][:code], JSON.generate(bind)
        end
      end

      it 'SECURITY: rejects a bind with one matching and one false binder - ALL stated binders must hold, not just some' do
        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(
          user_sig.call(challenge),
          attester_sig.call(challenge, robot, signed_metadata: { bind: { identifier: john[:identifier], via: 'https://wrong.example/' } })
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute res[:attested]
        assert_equal 'verification_failed', res[:error][:code]
      end

      it 'SECURITY: rejects a distinct attester whose bind carries a non-string binder value' do
        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(
          user_sig.call(challenge),
          attester_sig.call(challenge, robot, signed_metadata: { bind: { identifier: 123 } })
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute res[:attested]
        assert_equal 'verification_failed', res[:error][:code]
      end

      it 'tolerates unrecognized signedMetadata members outside bind - binders live only in bind, so top-level members (any name, any value) are auxiliary and ignored' do
        [
          { identifier: john[:identifier] },
          { sub: 'someone-else@example.com' },
          { tag: 'not-the-users-device-tag' },
          { issuedFor: 'a future member v1 knows nothing about' }
        ].each do |signed_metadata|
          challenge = build_challenge.call(robot_attestations)
          response = Triauth::MultiSignature.generate(
            user_sig.call(challenge),
            attester_sig.call(challenge, robot, signed_metadata: signed_metadata)
          )

          res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
          assert_equal true, res[:attested], JSON.generate(signed_metadata)
        end
      end

      it 'accepts a user segment whose bind states its own verified values - bind means the same on every segment of the envelope' do
        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(
          mk_sig.call(challenge, john[:devices][0][:keys], john[:identifier], user_via, { bind: { identifier: john[:identifier], via: user_via } }),
          attester_sig.call(challenge, robot)
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, res[:attested]
      end

      it 'SECURITY: rejects a user segment whose bind.identifier names someone else - every binder in the envelope must hold' do
        challenge = build_challenge.call(robot_attestations)
        response = Triauth::MultiSignature.generate(
          mk_sig.call(challenge, john[:devices][0][:keys], john[:identifier], user_via, { bind: { identifier: 'someone-else@example.com' } }),
          attester_sig.call(challenge, robot)
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute res[:attested]
        assert_equal 'verification_failed', res[:error][:code]
      end

      it 'SECURITY: rejects an envelope carrying a STRAY attester whose binder is false of the user - a false signed binding poisons the whole bundle, even when every requested attestation is satisfied by another segment' do
        attns = {
          'not-a-robot':   { label: 'I am not a robot',   providers: [robot[:via]] },
          'still-not-one': { label: 'I am still not one', providers: [robot[:via]] }
        }
        challenge = build_challenge.call(attns)
        response = Triauth::MultiSignature.generate(
          user_sig.call(challenge),
          attester_sig.call(challenge, robot), # satisfies both attestations (their provider lists overlap)
          attester_sig.call(challenge, robot, signed_metadata: { bind: { identifier: 'someone-else@example.com' } })
        )

        res = Triauth.attest({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute res[:attested]
        assert_equal 'verification_failed', res[:error][:code]
      end
    end
  end
end
