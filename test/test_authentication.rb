# frozen_string_literal: true

require_relative 'setup'
require_relative 'stubs/signer'
require_relative 'stubs/authenticator'
require_relative 'stubs/dns_resolver'
# The demo zone, served from the fixture: the suites resolve through it, as the triauth-js run does through test_unit.js
require_relative 'stubs/zone_resolver'
require 'json'
require 'uri'

# The fixtures: the identities with Symbol keys (compared to the port's Symbol-keyed results directly), the identifiers
# with String keys (the keys of `invalidIdentifiers` are identifier values, not property names); both guarded so that
# test.rb and a standalone run load them once (shared with test_identity.rb and test_validation.rb)
IDENTITIES = JSON.parse(File.read(File.expand_path('fixtures/identities.json', __dir__)), symbolize_names: true) unless defined?(IDENTITIES)
IDENTIFIERS_FIXTURE = JSON.parse(File.read(File.expand_path('fixtures/identifiers.json', __dir__))) unless defined?(IDENTIFIERS_FIXTURE)

describe 'Authentication API' do
  describe 'Triauth.authenticate' do
    it 'does not accept unrecognized options' do
      auth_res = Triauth.authenticate(
        {
          identifier: 'john@triauthdemo.org',
          callbackUrl: 'https://example.com/',
          unknownKey: 123
        }
      )

      refute auth_res[:authenticated]
      assert_equal 'invalid_arguments', auth_res[:error][:code]
    end

    describe 'accepts identifier and callbackUrl to produce challenge and redirectUrl' do
      identifier = 'john@triauthdemo.org'
      callback_url = 'http://localhost/'

      it 'returns challenge and a correct redirectUrl for valid identifiers' do
        auth_res = Triauth.authenticate(
          {
            identifier: 'john@triauthdemo.org',
            callbackUrl: 'https://example.com/'
          }
        )
        assert auth_res[:challenge]
        assert auth_res[:redirectUrl]
      end

      it 'encodes the identifier and callbackUrl in the challenge' do
        auth_res = Triauth.authenticate({ identifier: identifier, callbackUrl: callback_url })
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(auth_res[:challenge]))

        assert_equal identifier, challenge_request.data[:identifier]
        assert_equal callback_url, challenge_request.data[:cburl]
      end

      it 'accepts optional ext hash and encodes it in the challenge' do
        auth_res = Triauth.authenticate({ identifier: identifier, callbackUrl: callback_url, ext: { permissions: { ping: true } } })
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(auth_res[:challenge]))

        assert_equal true, challenge_request.data.dig(:ext, :permissions, :ping) # `ext?.permissions?.ping`
      end

      it 'accepts ext values with non-latin-1 characters and encodes them in the challenge' do
        # Regression: btoa()-based encoding used to throw on chars > U+00FF and surface as an internal error (internal_error)
        ext = { note: "Привет \u{1F389}" }
        auth_res = Triauth.authenticate({ identifier: identifier, callbackUrl: callback_url, ext: ext })

        assert_nil auth_res[:error], auth_res[:error].inspect
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(auth_res[:challenge]))
        assert_equal ext[:note], challenge_request.data.dig(:ext, :note)
      end

      it 'returns {error:{code:invalid_ext}} for ext with non-ASCII keys' do
        # safeParseJson rejects non-ASCII property names at stage 3, so validateExt must fail fast
        auth_res = Triauth.authenticate({ identifier: identifier, callbackUrl: callback_url, ext: { 'ключ': 'value' } })

        refute auth_res[:authenticated]
        assert_equal 'invalid_ext', auth_res[:error][:code]
      end

      it 'returns {error:{code:invalid_ext}} for ext values outside the JSON value rules' do
        # A lone surrogate has no UTF-8 encoding (safeParseJson refuses its escape at stage 3), and a JSON
        # number is a whole number of magnitude at most 2^53 - 1, the range every JSON parser reads exactly
        # (the lone surrogates of the JS strings are the ill-formed UTF-8-tagged byte strings they would occupy here)
        lone_high = "\xED\xA0\x80".dup.force_encoding('UTF-8')
        lone_low = "x\xED\xB0\x80".dup.force_encoding('UTF-8')
        invalid_exts = [{ a: lone_high }, { a: lone_low }, { nested: { a: lone_high } }, { a: Float::INFINITY }, { a: -Float::INFINITY }, { a: Float::NAN }, { nested: { a: Float::NAN } }, { a: 1.5 }, { a: 2**53 }, { nested: { a: -(2**53) } }]
        invalid_exts.each do |invalid_ext|
          auth_res = Triauth.authenticate({ identifier: identifier, callbackUrl: callback_url, ext: invalid_ext })

          refute auth_res[:authenticated]
          assert_equal 'invalid_ext', auth_res[:error][:code], invalid_ext.inspect
        end
      end

      it 'carries the documented manifest extension shape verbatim' do
        # The README's extension table: the registered manifest shape must pass the ext grammar
        manifest = { name: 'Fabulous Example', startUrl: 'https://example.com/', iconUrl: 'https://example.com/icon.png' }
        auth_res = Triauth.authenticate({ identifier: identifier, callbackUrl: callback_url, ext: { manifest: manifest } })

        assert_nil auth_res[:error], auth_res[:error].inspect
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(auth_res[:challenge]))
        assert_equal manifest, challenge_request.data.dig(:ext, :manifest)
      end

      it 'generates random and unique challenges for each call' do
        challenges = []

        (1..3).each do |_i|
          challenges.push(Triauth.authenticate({ identifier: identifier, callbackUrl: callback_url })[:challenge])
        end
        unique_challenges = challenges.uniq # `[...new Set(challenges)]`

        assert_equal challenges.length, unique_challenges.length
      end

      it 'returns validation error for invalid identifiers' do
        invalid_identifiers = IDENTIFIERS_FIXTURE['invalidIdentifiers'].dup # `emptyIdentifiers` is destructured and unused in triauth-js
        invalid_identifiers['123'] = 'non-string type' # `invalidIdentifiers[123] = ...`: JS stringifies the numeric key; added to a dup, so the fixture stays intact

        invalid_identifiers.each_key do |invalid_identifier|
          auth_res = Triauth.authenticate(
            {
              identifier: invalid_identifier,
              callbackUrl: '-'
            }
          )
          refute auth_res[:authenticated], invalid_identifier
          assert_equal 'invalid_identifier', auth_res[:error][:code], invalid_identifier
        end
      end

      it 'returns validation error for invalid callbackUrls' do
        invalid_urls = ['=', '', "http://localhost/#{'a' * 2048}"]

        invalid_urls.each do |invalid_url|
          auth_res = Triauth.authenticate(
            {
              identifier: 'john@triauthdemo.org',
              callbackUrl: invalid_url
            }
          )
          refute auth_res[:authenticated]
          assert_equal 'invalid_callback_url', auth_res[:error][:code]
        end
      end

      it 'returns domain_not_configured for a domain that is not configured for triauth' do
        auth_res = Triauth.authenticate(
          {
            identifier: 'john@example.com',
            callbackUrl: 'https://example.com/'
          }
        )

        refute auth_res[:authenticated]
        assert_equal 'domain_not_configured', auth_res[:error][:code]
      end

      it 'builds a challenge for an unknown identifier under a configured domain - existence is settled at stage 3, never probed at issue' do
        auth_res = Triauth.authenticate(
          {
            identifier: 'non-existing@triauthdemo.org',
            callbackUrl: 'https://example.com/'
          }
        )

        refute auth_res[:error]
        assert auth_res[:challenge]
        assert auth_res[:redirectUrl].start_with?('https://')
      end

      it 'returns DNS error for DNSSEC failed domains' do
        auth_res = Triauth.authenticate({ identifier: 'a@dnssec-failed.org', callbackUrl: 'https://example.com/' })

        refute auth_res[:authenticated]
        assert auth_res[:error]
        assert_equal 'dns_unavailable', auth_res[:error][:code]
      end

      it 'rejects the `sessionKey` option for the auth flow (only allowed for ping/attest/sign/stamp), and the `token` option' do
        [{ sessionKey: AuthenticatorStub::SESSION_KEY }, { token: ":#{'a' * 16}" }].each do |option|
          auth_res = Triauth.authenticate(
            {
              identifier: 'john@triauthdemo.org',
              callbackUrl: 'https://example.com/',
              **option
            }
          )

          refute auth_res[:authenticated]
          assert_equal 'invalid_arguments', auth_res[:error][:code], "#{option.keys[0]} for auth must surface as Unrecognized function argument"
        end
      end
    end

    describe 'accepts challenge and response to produce authentication result' do
      it 'correctly sets the authenticated status' do
        IDENTITIES.each_value do |identity|
          challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: 'https://example.com/' })[:challenge]

          identity[:devices].each do |device|
            signature = Triauth::Signature.generate(
              SignerStub.sign_using_device_keys(device[:keys]),
              'auth',
              identity[:identifier], '',
              'https://example.com/',
              AuthenticatorStub.public_challenge(challenge)
            )

            # Valid signatures should authenticate
            auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, signature) })

            assert_equal true, auth_res[:authenticated]

            assert_equal true, auth_res[:secure]
            assert auth_res[:expires] > Triauth::Helpers.date_now
            assert_equal identity[:identifier], auth_res[:identifier]
            assert_equal identity[:identityDomain], auth_res[:identityDomain]
            assert_equal '', auth_res[:actor]
            assert_equal '', auth_res[:actorIdentityDomain]
            assert_equal '', auth_res[:lookupCode], 'a public-mode identity consumes no lookup code'
            assert_equal '', auth_res[:actorLookupCode]
            assert_equal identity[:publicProfile], auth_res[:publicProfile]

            assert_equal device[:keys].length, auth_res[:keys].length
            assert_equal(true, auth_res[:keys].all? { |k| k[:verified] })

            assert_equal device[:deviceName], auth_res[:deviceName]
            # assert_equal device[:deviceTag], auth_res[:deviceTag]
            assert auth_res[:ext].is_a?(Hash) # `typeof authRes.ext === 'object'`

            # Milestone timeline: issued (stage 1) <= signed (stage 2) <= verified (stage 3), all numbers.
            assert auth_res[:issuedAt].is_a?(Integer) # `typeof === 'number'`: timestamps are Integers here
            assert auth_res[:signedAt].is_a?(Integer)
            assert auth_res[:verifiedAt].is_a?(Integer)
            assert auth_res[:signedAt].between?(auth_res[:issuedAt], auth_res[:verifiedAt]) # `issuedAt <= signedAt && signedAt <= verifiedAt`

            # Invalid signature should not authenticate
            auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, signature.sub('@', '@a')) })
            refute auth_res[:authenticated], 'invalid signatures must not be authenticated'
            refute auth_res[:identifier]
          end
        end
      end

      it 'correctly sets the ext property' do
        signed_data = { ext: { key: 'value', 'nested-object': { a: 'b' } } }
        unsigned_data = { a: 'b' }

        IDENTITIES.each_value do |identity|
          challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: 'https://example.com/' })[:challenge]

          identity[:devices].each do |device|
            response = Triauth::Signature.generate(
              SignerStub.sign_using_device_keys(device[:keys]),
              'auth',
              identity[:identifier], '',
              'https://example.com/',
              AuthenticatorStub.public_challenge(challenge),
              signed_data,
              unsigned_data
            )

            auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })

            assert_equal true, auth_res[:authenticated]
            assert_equal identity[:identifier], auth_res[:identifier]
            assert_equal device[:deviceName], auth_res[:deviceName]

            assert_equal signed_data[:ext], auth_res[:ext]
          end
        end
      end

      it 'round-trips ext values with non-latin-1 characters' do
        # Regression: stage 1 used to fail with internal_error (btoa throw) and stage 3 decoded UTF-8 as mojibake (atob)
        signed_data = { ext: { emoji: "\u{1F389}\u{1F680}", cyrillic: 'тест' } }

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: 'https://example.com/', ext: { note: "Привет \u{1F389}" } })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'auth',
          identity[:identifier], '',
          'https://example.com/',
          AuthenticatorStub.public_challenge(challenge),
          signed_data
        )

        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })

        assert_equal true, auth_res[:authenticated]
        assert_equal signed_data[:ext], auth_res[:ext]
      end

      it 'caps secure at the DNSSEC status of the triauth configuration record' do
        # The endpoint record selects the identity domain the keys are read from (mode/len options),
        # so even DNSSEC-validated key records must not yield secure:true when the endpoint
        # record itself was not validated.
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        key_records = device[:keys].each_with_index.map do |key, idx|
          {
            value: "key #{device[:deviceName]}[#{idx + 1}/#{device[:keys].length}]:#{key[:public]} type=es256",
            ttl: 1800,
            dnssec: true
          }
        end

        [[true, true], [false, false], [nil, false]].each do |endpoint_dnssec, expected_secure| # `[undefined, false]`: nil
          resolver = DnsResolverStub.new(
            {
              'triauthdemo.org': { TXT: [{ value: 'triauth auth.triauthdemo.org mode=public', ttl: 1800, dnssec: endpoint_dnssec }] },
              'john._at.triauthdemo.org': { TXT: key_records }
            }
          )

          challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: 'https://example.com/' }, { resolver: resolver })[:challenge]
          response = Triauth::Signature.generate(
            SignerStub.sign_using_device_keys(device[:keys]),
            'auth',
            identity[:identifier], '',
            'https://example.com/',
            AuthenticatorStub.public_challenge(challenge)
          )

          auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) }, { resolver: resolver })

          assert_equal true, auth_res[:authenticated], "authentication must succeed for endpoint dnssec:#{endpoint_dnssec.inspect}"
          assert_equal expected_secure, auth_res[:secure], "endpoint dnssec:#{endpoint_dnssec.inspect} must yield secure:#{expected_secure}"
        end
      end

      it 'rejects an otherwise-valid auth with error dnssec_required when config.requireSecure is set and the result is not DNSSEC-secure' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        key_records = lambda do |dnssec|
          device[:keys].each_with_index.map do |key, idx|
            {
              value: "key #{device[:deviceName]}[#{idx + 1}/#{device[:keys].length}]:#{key[:public]} type=es256",
              ttl: 1800,
              dnssec: dnssec
            }
          end
        end

        [true, false].each do |secure|
          resolver = DnsResolverStub.new(
            {
              'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=public'] },
              'john._at.triauthdemo.org': { TXT: key_records.call(secure) }
            }
          )

          challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: 'https://example.com/' }, { resolver: resolver })[:challenge]
          response = Triauth::Signature.generate(
            SignerStub.sign_using_device_keys(device[:keys]),
            'auth',
            identity[:identifier], '',
            'https://example.com/',
            AuthenticatorStub.public_challenge(challenge)
          )

          # Default (requireSecure off): authenticates regardless of `secure`.
          auth_default = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) }, { resolver: resolver })
          assert_equal true, auth_default[:authenticated], "default config must authenticate (secure:#{secure})"
          assert_equal secure, auth_default[:secure]

          # requireSecure on: a DNSSEC-secure result still authenticates; a non-secure one is rejected with dnssec_required.
          auth_strict = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) }, { resolver: resolver, requireSecure: true })
          if secure
            assert_equal true, auth_strict[:authenticated], 'DNSSEC-secure result must still authenticate under requireSecure'
            assert_equal true, auth_strict[:secure]
          else
            refute auth_strict[:authenticated], 'non-DNSSEC result must not authenticate under requireSecure'
            assert_equal 'dnssec_required', auth_strict[:error][:code]
            assert_equal 'Your domain does not support DNSSEC, which is required to continue.', auth_strict[:error][:message]
          end
        end
      end

      it 'authenticates with ed25519 keys (type=ed25519 key records)' do
        # A fixed OKP/Ed25519 fixture pair; `public` is the 32-byte raw public key (base64url) as published in DNS
        ed25519_key = {
          public: 'Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0',
          private: { kty: 'OKP', crv: 'Ed25519', d: '-_UnNRraY7oJRq-G3bKgtnbM9y1AhAoj0zjAYr810yM', x: 'Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0' }
        }

        identifier = 'john@triauthdemo.org'
        callback_url = 'https://example.com/'

        resolver = DnsResolverStub.new(
          {
            'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=public'] },
            'john._at.triauthdemo.org': { TXT: ["key device[1/1]:#{ed25519_key[:public]} type=ed25519"] }
          }
        )

        challenge = Triauth.authenticate({ identifier: identifier, callbackUrl: callback_url }, { resolver: resolver })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys([ed25519_key]),
          'auth',
          identifier, '',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )

        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) }, { resolver: resolver })

        assert_equal true, auth_res[:authenticated], 'authentication backed by an ed25519 key must succeed'
        assert_equal identifier, auth_res[:identifier]
        assert_equal 'ed25519', auth_res[:keys][0][:options][:type]
        assert_equal true, auth_res[:keys][0][:verified]
      end

      it 'verifies identifier, if passed, is the same as in challenge' do
        identifier = IDENTITIES[:john][:identifier]

        challenge = Triauth.authenticate({ identifier: identifier, callbackUrl: 'https://example.com/' })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(IDENTITIES[:john][:devices][0][:keys]),
          'auth',
          identifier, '',
          'https://example.com/',
          AuthenticatorStub.public_challenge(challenge)
        )

        auth_res = Triauth.authenticate({ identifier: identifier, challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, auth_res[:authenticated]

        auth_res = Triauth.authenticate({ identifier: 'other-user@example.com', challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute auth_res[:authenticated]
      end

      it 'does not authenticate challenges with invalid or unresolvable identifier' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: 'https://example.com/' })[:challenge]
        decoded_challenge = JSON.parse(Triauth::Helpers.base64url_to_string(AuthenticatorStub.public_challenge(challenge)), symbolize_names: true)

        assert_equal identity[:identifier], decoded_challenge[:identifier]

        # first identifier is valid (to check if this test is working correctly), the rest not
        [identity[:identifier], 'john@domain.invalid', 'john@triauth.org', 'not-existing@triauthdemo.org', '!', ''].each do |identifier|
          decoded_challenge[:identifier] = identifier
          modified_challenge = AuthenticatorStub.reencode(challenge, decoded_challenge)

          response = Triauth::Signature.generate(
            SignerStub.sign_using_device_keys(device[:keys]),
            'auth',
            identifier, '',
            'https://example.com/',
            AuthenticatorStub.public_challenge(challenge)
          )

          auth_res = Triauth.authenticate({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })

          assert_equal(identifier == identity[:identifier], auth_res[:authenticated] == true) # `!!authRes?.authenticated`
        end
      end

      it 'does not authenticate expired challenges' do
        # challenge with iat set far in the past; built dynamically
        challenge = AuthenticatorStub.store(
          {
            type: 'auth',
            identifier: 'john@triauthdemo.org',
            nonce: 'wtr6JVXFUZJBJULti3aYZo5A',
            iat: 1_737_711_045_465,
            ver: 1
          }
        )

        auth_res = Triauth.authenticate(
          {
            challenge: challenge,
            response: AuthenticatorStub.seal(challenge, '|auth;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|')
          }
        )

        assert_equal false, auth_res[:authenticated] == true # `!!authRes?.authenticated`
        assert_equal 'request_expired', auth_res[:error][:code]
      end

      it 'does not authenticate challenges with issued at (iat) in future' do
        # challenge with iat set far in the future; built dynamically
        challenge = AuthenticatorStub.store(
          {
            type: 'auth',
            identifier: 'john@triauthdemo.org',
            nonce: 'wtr6JVXFUZJBJULti3aYZo5A',
            iat: 99_999_999_999_999,
            ver: 1
          }
        )

        auth_res = Triauth.authenticate(
          {
            challenge: challenge,
            response: AuthenticatorStub.seal(challenge, '|auth;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|')
          }
        )

        assert_equal false, auth_res[:authenticated] == true # `!!authRes?.authenticated`
        assert_equal 'request_expired', auth_res[:error][:code]
      end

      # The next two tests are `(done)`-style in triauth-js, where the `.catch(() => assert(false))` inside
      # `Promise.allSettled` swallows the assertion; here every value is asserted (an escaping exception fails the test).
      # `void 0` is the key left out, `null` is nil, the rest are the literals.
      it 'does not authenticate invalid challenges' do
        response = '|auth;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|'

        auth_res = Triauth.authenticate({ response: response })
        refute auth_res[:authenticated], 'void 0'
        [nil, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ'].each do |invalid_challenge|
          auth_res = Triauth.authenticate({ challenge: invalid_challenge, response: response })
          refute auth_res[:authenticated], invalid_challenge.inspect
        end
      end

      it 'does not authenticate invalid responses' do
        challenge = 'eyJzdWIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoid3RyNkpWWEZVWkpCSlVMdGkzYVlabzVBIiwiaWF0IjoxNzM3NzExMDQ1NDY1LCJ2ZXIiOjF9'

        auth_res = Triauth.authenticate({ challenge: challenge })
        refute auth_res[:authenticated], 'void 0'
        [nil, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ'].each do |invalid_response|
          auth_res = Triauth.authenticate({ challenge: challenge, response: invalid_response })
          refute auth_res[:authenticated], invalid_response.inspect
        end
      end

      it 'rejects challenges whose embedded `type` does not match the auth flow' do
        # An attacker who substitutes the challenge's `type` field with another flow's value
        # must be rejected at Stage 3 with verification_failed before any DNS or signature work.
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        build_res = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: callback_url })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:type] = 'sign' # tamper
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'auth',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(modified_challenge)
        )

        auth_res = Triauth.authenticate({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute auth_res[:authenticated]
        assert_equal 'verification_failed', auth_res[:error][:code]
      end

      it 'rejects responses whose envelope `type` does not match the auth flow' do
        # Even if the challenge says `auth`, a signature minted with envelope type='sign'
        # must be rejected by the signature.verify type constraint.
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign', # <-- envelope type mismatched with the flow
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )

        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute auth_res[:authenticated]
        assert_equal 'verification_failed', auth_res[:error][:code]
      end

      it 'verifies callbackUrl, if passed, is the same as in challenge' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'auth',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )

        # Matching callbackUrl — succeeds
        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response), callbackUrl: callback_url })
        assert_equal true, auth_res[:authenticated]

        # Mismatching callbackUrl — fails with verification_failed
        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response), callbackUrl: 'https://other-domain.com/' })
        refute auth_res[:authenticated]
        assert_equal 'verification_failed', auth_res[:error][:code]
      end

      it 'rejects responses whose signed `via` is not a prefix of the challenge `cburl`' do
        # Defense-in-depth (S2): under a non-DNSSEC domain, attacker-controlled keys could sign
        # with a misaligned `via`. Even though the signature is cryptographically valid against
        # the attacker's published key, the via/cburl mismatch must reject the auth.
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/triauth-callback'

        challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]

        # Sanity: a via that is a proper prefix of cburl authenticates
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'auth',
          identity[:identifier], '',
          'https://example.com/',
          AuthenticatorStub.public_challenge(challenge)
        )
        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, auth_res[:authenticated], 'via prefixing cburl must authenticate'

        # A via on a different domain must fail
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'auth',
          identity[:identifier], '',
          'https://attacker.example/',
          AuthenticatorStub.public_challenge(challenge)
        )
        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute auth_res[:authenticated], 'via not a prefix of cburl must NOT authenticate'
      end

      it 'honors per-call authTimeout override (config #1)' do
        # Default 3-minute window should reject an iat just outside it; a widened per-call
        # authTimeout override should accept the same iat.
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'
        default_timeout = Triauth.config[:authTimeout]

        build_res = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: callback_url })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        # Move iat 10 seconds past the default window
        challenge_obj.data[:iat] = Triauth::Helpers.date_now - (default_timeout + 10_000)
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'auth',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(modified_challenge)
        )

        # Default config — should fail with request_expired (expired)
        auth_res = Triauth.authenticate({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute auth_res[:authenticated], 'default authTimeout must reject iat outside window'
        assert_equal 'request_expired', auth_res[:error][:code]

        # Override widens the window — should succeed
        auth_res = Triauth.authenticate(
          { challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) },
          { authTimeout: (default_timeout * 2) + 60_000 }
        )
        assert_equal true, auth_res[:authenticated], 'per-call authTimeout override must accept iat within widened window'
      end

      it 'does NOT prevent in-window replay (caller is responsible for invalidating challenges)' do
        # The library deliberately does not track consumed challenges; replay protection is the
        # caller's responsibility (see README). This test documents that contract — if it ever
        # changes (e.g., internal tracking is added), the contract change must be deliberate.
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'auth',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )

        first = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, first[:authenticated]

        second = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, second[:authenticated], 'library does not track consumed challenges — caller must'
      end

      it 'still authenticates when unsignedMetadata is tampered with after signing' do
        # The unsignedMetadata slot in the signature envelope is intentionally NOT covered by the
        # crypto signature. Verifiers that consume unsignedMetadata must independently bind the
        # consumed fields (see WebAuthn). For ECDSA auth, no field is consumed from unsignedMetadata,
        # so tampering must not affect the outcome.
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'auth',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )

        # Inject a tampered unsignedMetadata segment into the wire envelope
        segments = response[1...-1].split(';', -1)
        # segments[7] is the unsignedMetadata slot
        segments[7] = Triauth::Helpers.string_to_base64url(JSON.generate({ tampered: 'evilValue' }))
        tampered_response = "|#{segments.join(';')}|"

        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, tampered_response) })
        assert_equal true, auth_res[:authenticated], 'tampered unsignedMetadata must NOT invalidate ECDSA auth'
      end

      # An auth envelope signed by john's first device over the public challenge, carrying the signed and unsigned
      # metadata slots as the given JSON texts (nil for an empty slot), joined and wrapped the way `Signature.generate`
      # does it: `generate` would re-serialize a Hash, and these texts can never come from one.
      envelope_with_metadata = lambda do |challenge, signed_json, unsigned_json|
        identity = IDENTITIES[:john]
        encoded_signed = signed_json.nil? ? '' : Triauth::Helpers.string_to_base64url(signed_json)
        encoded_unsigned = unsigned_json.nil? ? '' : Triauth::Helpers.string_to_base64url(unsigned_json)
        slots = ['auth', identity[:identifier], '', 'https://example.com/', 'v1', Triauth::Helpers.date_now.to_s, encoded_signed, '', AuthenticatorStub.public_challenge(challenge)]
        crypto_signatures = SignerStub.from_device_keys(identity[:devices][0][:keys]).sign(slots.join(';'))
        slots[7] = encoded_unsigned
        slots[8] = crypto_signatures.join(';')
        "|#{slots.join(';')}|"
      end

      it 'reports a signed ext carrying a non-finite or non-safe-integer number literal as invalid_signature, and keeps an integral float as its integer (port-only)' do
        # `safe_parse_json` parses `1e400` to Infinity exactly as JS does, and since cb8e61c its walk admits safe integers only, so the
        # metadata is malformed as a whole: the envelope is refused with invalid_signature ahead of any ext handling, as the reference
        # does (auth.json pins `1e400` and `9007199254740993` over the frozen clock); an integral float is the integer it is in JS
        challenge = Triauth.authenticate({ identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/' })[:challenge]
        ['{"ext":{"a":1e400,"n":{"b":-1e400},"c":"x"}}', '{"ext":{"a":9007199254740993}}', '{"ext":{"n":{"b":-9007199254740992}}}', '{"ext":{"a":1.5}}'].each do |signed_json|
          response = envelope_with_metadata.call(challenge, signed_json, nil)
          auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
          refute auth_res[:authenticated], [signed_json, auth_res].inspect
          assert_equal 'invalid_signature', auth_res[:error][:code], signed_json
        end
        response = envelope_with_metadata.call(challenge, '{"ext":{"a":9007199254740991,"b":1.0}}', nil)
        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, auth_res[:authenticated], auth_res.inspect
        assert_equal({ a: 9_007_199_254_740_991, b: 1 }, auth_res[:ext])
        assert_instance_of Integer, auth_res[:ext][:b]
      end

      it 'rejects metadata carrying a lone surrogate escape in a signed ext value, an ignored signed member and an unsigned member with invalid_signature (port-only)' do
        # the reference parses the escape into a lone surrogate and refuses it at parse time, in every slot and member
        # (auth.json pins the signed and the unsigned ext value); the source gate refuses the escape here, with the same invalid_signature
        challenge = Triauth.authenticate({ identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.com/' })[:challenge]
        [
          ['{"ext":{"a":"\\ud800"}}', nil],
          ['{"ext":{"a":"\\udc00","b":"x\\udfff\\ud800y"}}', nil],
          ['{"x":"\\ud800"}', nil],
          [nil, '{"u":"\\ud800"}'],
          ['{"ext":{"a":"\\ud83d\\ude00"}}', '{"u":"\\udc00"}']
        ].each do |signed_json, unsigned_json|
          response = envelope_with_metadata.call(challenge, signed_json, unsigned_json)
          auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
          refute auth_res[:authenticated], [signed_json, unsigned_json, auth_res].inspect
          assert_equal 'invalid_signature', auth_res[:error][:code], [signed_json, unsigned_json].inspect
        end
        # a surrogate pair in a signed ext value is one code point: the envelope authenticates and carries it
        response = envelope_with_metadata.call(challenge, '{"ext":{"a":"\\ud83d\\ude00"}}', nil)
        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, auth_res[:authenticated], auth_res.inspect
        assert_equal({ a: "\u{1F600}" }, auth_res[:ext])
      end
    end

    describe 'delegated authentication (include grants)' do
      subject_device = IDENTITIES[:john][:devices][0] # the subject's own device key
      actor_device   = IDENTITIES[:john][:devices][1] # a second fixture keypair, serving as the actor's device
      callback_url = 'https://example.com/'

      resolver = lambda do |include_records|
        DnsResolverStub.new(
          {
            'example.org': { TXT: [{ value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 1800, dnssec: true }] },
            'john._at.example.org': {
              TXT: [
                { value: "key desktop[1/1]:#{subject_device[:keys][0][:public]}", ttl: 1800, dnssec: true },
                *include_records
              ]
            },
            'issuer.example': { TXT: [{ value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true }] },
            'actor._at.issuer.example': {
              TXT: [
                { value: "key remote[1/2]:#{actor_device[:keys][0][:public]}", ttl: 1800, dnssec: true },
                { value: "key remote[2/2]:#{actor_device[:keys][1][:public]}", ttl: 1800, dnssec: true }
              ]
            }
          }
        )
      end

      # Runs the full flow with the actor's keys signing on behalf of john@example.org
      delegated_auth = lambda do |include_records, cburl = callback_url|
        config = { resolver: resolver.call(include_records) }
        challenge = Triauth.authenticate({ identifier: 'john@example.org', callbackUrl: cburl }, config)[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(actor_device[:keys]),
          'auth',
          'john@example.org', 'actor@issuer.example',
          cburl,
          AuthenticatorStub.public_challenge(challenge)
        )
        return { config: config, authRes: Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) }, config) }
      end

      it 'authenticates the subject through a granted actor, with the composite deviceTag' do
        include_record = { value: 'include actor@issuer.example scope=any', ttl: 900, dnssec: true }
        config, auth_res = delegated_auth.call([include_record]).values_at(:config, :authRes)

        assert_equal true, auth_res[:authenticated]
        assert_equal 'john@example.org', auth_res[:identifier]
        assert_equal 'actor@issuer.example', auth_res[:actor]
        assert_equal 'john._at.example.org', auth_res[:identityDomain]
        assert_equal 'actor._at.issuer.example', auth_res[:actorIdentityDomain], "the actor's identity domain names the records the signing keys were read from"
        assert_equal '', auth_res[:lookupCode], 'public-mode identities consume no lookup code'
        assert_equal '', auth_res[:actorLookupCode]
        assert_equal 'remote', auth_res[:deviceName], 'device fields must describe the actor device that signed'
        assert_equal true, auth_res[:secure]

        include_tag, actor_identifier, actor_device_tag = auth_res[:deviceTag].split(':', -1)
        assert_equal 'actor@issuer.example', actor_identifier
        assert_match(/\A[A-Za-z0-9_-]{43}\z/, actor_device_tag)

        subject = Triauth::Identity.new('john@example.org', {}, config)
        subject.resolve
        assert_equal subject.includes.includes[0][:tag], include_tag, 'the deviceTag must pin the exact grant'

        # The include record's 900s TTL is shorter than the key records' - earliest wins
        assert auth_res[:expires] > Triauth::Helpers.date_now + 800_000 && auth_res[:expires] <= Triauth::Helpers.date_now + 900_000
      end

      it "carries the subject's groups on the result, never the actor's" do
        config = {
          resolver: DnsResolverStub.new(
            {
              'example.org': { TXT: [{ value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 1800, dnssec: true }] },
              'john._at.example.org': {
                TXT: [
                  { value: "key desktop[1/1]:#{subject_device[:keys][0][:public]}", ttl: 1800, dnssec: true },
                  { value: 'include actor@issuer.example scope=any', ttl: 1800, dnssec: true },
                  { value: 'groups admins,project3', ttl: 1800, dnssec: true }
                ]
              },
              'issuer.example': { TXT: [{ value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true }] },
              'actor._at.issuer.example': {
                TXT: [
                  { value: "key remote[1/2]:#{actor_device[:keys][0][:public]}", ttl: 1800, dnssec: true },
                  { value: "key remote[2/2]:#{actor_device[:keys][1][:public]}", ttl: 1800, dnssec: true },
                  { value: 'groups contractors', ttl: 1800, dnssec: true }
                ]
              }
            }
          )
        }

        challenge = Triauth.authenticate({ identifier: 'john@example.org', callbackUrl: callback_url }, config)[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(actor_device[:keys]),
          'auth',
          'john@example.org', 'actor@issuer.example',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )
        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) }, config)

        assert_equal true, auth_res[:authenticated]
        assert_equal ['admins@example.org', 'project3@example.org'], auth_res[:groups], "the subject's groups, qualified with the subject's domain - the actor's own groups must not leak in"
      end

      it 'caps secure at the DNSSEC status of the include record' do
        auth_res = delegated_auth.call([{ value: 'include actor@issuer.example scope=any', ttl: 1800, dnssec: false }])[:authRes]

        assert_equal true, auth_res[:authenticated]
        assert_equal false, auth_res[:secure]
      end

      it 'bounds expires by the subject endpoint record TTL when it is the shortest-lived record' do
        config = {
          resolver: DnsResolverStub.new(
            {
              'example.org': { TXT: [{ value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 60, dnssec: true }] },
              'john._at.example.org': {
                TXT: [
                  { value: "key desktop[1/1]:#{subject_device[:keys][0][:public]}", ttl: 1800, dnssec: true },
                  { value: 'include actor@issuer.example scope=any', ttl: 1800, dnssec: true }
                ]
              },
              'issuer.example': { TXT: [{ value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true }] },
              'actor._at.issuer.example': {
                TXT: [
                  { value: "key remote[1/2]:#{actor_device[:keys][0][:public]}", ttl: 1800, dnssec: true },
                  { value: "key remote[2/2]:#{actor_device[:keys][1][:public]}", ttl: 1800, dnssec: true }
                ]
              }
            }
          )
        }
        challenge = Triauth.authenticate({ identifier: 'john@example.org', callbackUrl: callback_url }, config)[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(actor_device[:keys]), 'auth', 'john@example.org', 'actor@issuer.example', callback_url, AuthenticatorStub.public_challenge(challenge)
        )
        before = Triauth::Helpers.date_now
        auth_res = Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) }, config)

        assert_equal true, auth_res[:authenticated]
        assert auth_res[:expires].between?(before + 60_000, Triauth::Helpers.date_now + 60_000), 'the subject endpoint record expires first' # `expires >= before + 60_000 && expires <= Date.now() + 60_000`
      end

      it 'rejects (verification_failed) a delegated response with no include grant for the actor' do
        auth_res = delegated_auth.call([])[:authRes]

        refute auth_res[:authenticated]
        assert_equal 'verification_failed', auth_res[:error][:code]
      end

      it 'rejects (verification_failed) a delegated response whose grant does not cover the auth flow (use=sign)' do
        auth_res = delegated_auth.call([{ value: 'include actor@issuer.example use=sign scope=any', ttl: 1800, dnssec: true }])[:authRes]

        refute auth_res[:authenticated]
        assert_equal 'verification_failed', auth_res[:error][:code]
      end

      it 'rejects (verification_failed) a delegated response whose grant publishes no scope option - the record is ignored as a whole' do
        auth_res = delegated_auth.call([{ value: 'include actor@issuer.example', ttl: 1800, dnssec: true }])[:authRes]

        refute auth_res[:authenticated]
        assert_equal 'verification_failed', auth_res[:error][:code]
      end

      it 'authenticates through a grant scoped to the service host (scope=example.com)' do
        auth_res = delegated_auth.call([{ value: 'include actor@issuer.example scope=example.com', ttl: 1800, dnssec: true }])[:authRes]

        assert_equal true, auth_res[:authenticated]
        assert_equal 'actor@issuer.example', auth_res[:actor]
      end

      it 'SECURITY: rejects (verification_failed) a delegated response whose grant is scoped to a different host (scope=other.example)' do
        auth_res = delegated_auth.call([{ value: 'include actor@issuer.example scope=other.example', ttl: 1800, dnssec: true }])[:authRes]

        refute auth_res[:authenticated]
        assert_equal 'verification_failed', auth_res[:error][:code]
      end

      it 'matches scope on the bare host: an IPv4 callback on a non-default port is covered by its quad entry' do
        auth_res = delegated_auth.call(
          [{ value: 'include actor@issuer.example scope=10.0.0.5', ttl: 1800, dnssec: true }],
          'http://10.0.0.5:8080/'
        )[:authRes]

        assert_equal true, auth_res[:authenticated]
        assert_equal 'actor@issuer.example', auth_res[:actor]
      end

      it 'authenticates through a scope=any grant at any callback host - an IPv4 callback on a non-default port included' do
        auth_res = delegated_auth.call(
          [{ value: 'include actor@issuer.example scope=any', ttl: 1800, dnssec: true }],
          'http://10.0.0.5:8080/'
        )[:authRes]

        assert_equal true, auth_res[:authenticated]
        assert_equal 'actor@issuer.example', auth_res[:actor]
      end

      it 'SECURITY: rejects (verification_failed) when the grant lists any beside a host (scope=example.com,any) - any is only the sole-entry spelling, so the record is ignored as a whole' do
        auth_res = delegated_auth.call([{ value: 'include actor@issuer.example scope=example.com,any', ttl: 1800, dnssec: true }])[:authRes]

        refute auth_res[:authenticated]
        assert_equal 'verification_failed', auth_res[:error][:code]
      end
    end

    describe 'sealed responses' do
      identity = IDENTITIES[:john]
      callback_url = 'https://example.com/'

      # Stage 1, and the plain envelope the authenticator signs for it
      start_flow = lambda do
        challenge = Triauth.authenticate({ identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]
        envelope = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(identity[:devices][0][:keys]), 'auth', identity[:identifier], '', callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )
        return { challenge: challenge, envelope: envelope }
      end

      it 'stores the challenge with its decryption key, and puts the encryption key into the challenge' do
        challenge = start_flow.call[:challenge]
        public_challenge, decryption_key, rest = challenge.split('.', -1)

        assert_match(/\A[A-Za-z0-9_-]{43}\z/, decryption_key)
        assert_nil rest
        assert_match(/\A[A-Za-z0-9_-]{87}\z/, Triauth::Challenge.from_string(public_challenge).data[:ek])
      end

      it 'authenticates a sealed response, and refuses the plain envelope for a challenge with a key (invalid_response)' do
        challenge, envelope = start_flow.call.values_at(:challenge, :envelope)

        assert_equal true, Triauth.authenticate({ challenge: challenge, response: AuthenticatorStub.seal(challenge, envelope) })[:authenticated]

        plain_res = Triauth.authenticate({ challenge: challenge, response: envelope })
        refute plain_res[:authenticated]
        assert_equal 'invalid_response', plain_res[:error][:code]
      end

      it 'refuses a challenge stored without its decryption key (invalid_challenge)' do
        challenge, envelope = start_flow.call.values_at(:challenge, :envelope)
        auth_res = Triauth.authenticate({ challenge: AuthenticatorStub.public_challenge(challenge), response: envelope })

        refute auth_res[:authenticated]
        assert_equal 'invalid_challenge', auth_res[:error][:code]
      end

      it 'refuses a decryption key on a challenge without `ek` (invalid_challenge)' do
        challenge, envelope = start_flow.call.values_at(:challenge, :envelope)
        data = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(challenge)).data
        ek = data[:ek]
        data.delete(:ek)
        stored = AuthenticatorStub.reencode(challenge, data)

        auth_res = Triauth.authenticate({ challenge: stored, response: Triauth::ResponseCipher.seal(ek, envelope)[:sealedResponse] })
        refute auth_res[:authenticated]
        assert_equal 'invalid_challenge', auth_res[:error][:code]
      end

      it 'refuses a challenge without `ek` or key, even with the plain envelope signed for it (invalid_challenge)' do
        challenge = start_flow.call[:challenge]
        data = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(challenge)).data
        data.delete(:ek)
        bare = Triauth::Helpers.string_to_base64url(JSON.generate(data))
        envelope = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(identity[:devices][0][:keys]), 'auth', identity[:identifier], '', callback_url, bare
        )

        auth_res = Triauth.authenticate({ challenge: bare, response: envelope })
        refute auth_res[:authenticated]
        assert_equal 'invalid_challenge', auth_res[:error][:code]
      end

      it 'refuses a stored challenge whose `ek` is malformed (invalid_challenge)' do
        challenge, envelope = start_flow.call.values_at(:challenge, :envelope)
        response = AuthenticatorStub.seal(challenge, envelope)
        data = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(challenge)).data

        [data[:ek][1..], "#{data[:ek]}A", 42].each do |ek|
          auth_res = Triauth.authenticate({ challenge: AuthenticatorStub.reencode(challenge, data.merge({ ek: ek })), response: response }) # `{...data, ek}`
          refute auth_res[:authenticated], ek.to_s[0, 12]
          assert_equal 'invalid_challenge', auth_res[:error][:code], ek.to_s[0, 12]
        end
      end

      it 'refuses a malformed decryption key suffix (invalid_challenge)' do
        challenge, envelope = start_flow.call.values_at(:challenge, :envelope)
        response = AuthenticatorStub.seal(challenge, envelope)
        public_challenge, decryption_key = challenge.split('.', -1)

        # (`decryptionKey.replace(/.$/, '!')`: the last character of a base64url key, which holds no line terminator)
        ["#{challenge}A", "#{public_challenge}.#{decryption_key[1..]}", "#{public_challenge}.", "#{challenge}.#{decryption_key}", "#{public_challenge}.#{decryption_key.sub(/[A-Za-z0-9_-]\z/, '!')}"].each do |stored|
          auth_res = Triauth.authenticate({ challenge: stored, response: response })
          refute auth_res[:authenticated], stored[-12..]
          assert_equal 'invalid_challenge', auth_res[:error][:code], stored[-12..]
        end
      end

      it 'refuses a response sealed for another challenge, or changed in transit (invalid_response)' do
        first = start_flow.call
        second = start_flow.call
        response = AuthenticatorStub.seal(first[:challenge], first[:envelope])

        other_res = Triauth.authenticate({ challenge: second[:challenge], response: response })
        refute other_res[:authenticated]
        assert_equal 'invalid_response', other_res[:error][:code]

        tampered = "#{response[0...-5]}#{response[-5] == 'A' ? 'B' : 'A'}#{response[-4..]}"
        tampered_res = Triauth.authenticate({ challenge: first[:challenge], response: tampered })
        refute tampered_res[:authenticated]
        assert_equal 'invalid_response', tampered_res[:error][:code]
      end

      it 'refuses a well-sealed response whose plaintext is not a response envelope (invalid_response)' do
        challenge = start_flow.call[:challenge]
        ek = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(challenge)).data[:ek]
        auth_res = Triauth.authenticate({ challenge: challenge, response: Triauth::ResponseCipher.seal(ek, 'not-an-envelope')[:sealedResponse] })

        refute auth_res[:authenticated]
        assert_equal 'invalid_response', auth_res[:error][:code]
      end

      it 'keeps the denial plain: `false` is request_denied for a challenge with a key' do
        challenge = start_flow.call[:challenge]
        auth_res = Triauth.authenticate({ challenge: challenge, response: 'false' })

        refute auth_res[:authenticated]
        assert_equal 'request_denied', auth_res[:error][:code]
      end
    end
  end

  describe 'Triauth.ping' do
    describe 'accepts identifier, callbackUrl, and sessionKey to produce challenge and redirectUrl' do
      identifier = 'john@triauthdemo.org'
      callback_url = 'https://example.com/'
      session_key = AuthenticatorStub::SESSION_KEY

      it 'returns challenge and a correct redirectUrl for valid identifiers' do
        ping_res = Triauth.ping({ identifier: identifier, callbackUrl: callback_url, sessionKey: session_key })
        assert ping_res[:challenge].is_a?(String) && ping_res[:challenge].length > 0
        assert ping_res[:redirectUrl].is_a?(String) && ping_res[:redirectUrl].length > 0
      end

      it 'seals the challenge into redirectUrl under the session key, next to its skid' do
        ping_res = Triauth.ping({ identifier: identifier, callbackUrl: callback_url, sessionKey: session_key })
        assert ping_res[:redirectUrl].include?('#?skid=') && ping_res[:redirectUrl].include?('&request=')
        refute ping_res[:redirectUrl].include?('challenge=') || ping_res[:redirectUrl].include?('token=')
      end

      it 'rejects a request without a session key with invalid_session_key - ping follows a sign-in' do
        ping_res = Triauth.ping({ identifier: identifier, callbackUrl: callback_url })
        assert_equal 'invalid_session_key', ping_res.dig(:error, :code) # `pingRes?.error?.code`
      end

      it 'encodes type, identifier and callbackUrl in the challenge' do
        ping_res = Triauth.ping({ identifier: identifier, callbackUrl: callback_url, sessionKey: session_key })
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(ping_res[:challenge]))

        assert_equal 'ping', challenge_request.data[:type]
        assert_equal identifier, challenge_request.data[:identifier]
        assert_equal callback_url, challenge_request.data[:cburl]
        assert_equal 1, challenge_request.data[:ver]
      end

      it 'accepts optional ext hash and encodes it in the challenge' do
        ping_res = Triauth.ping({ identifier: identifier, callbackUrl: callback_url, sessionKey: session_key, ext: { foo: 'bar' } })
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(ping_res[:challenge]))

        assert_equal 'bar', challenge_request.data.dig(:ext, :foo) # `ext?.foo`
      end

      it 'generates random and unique challenges for each call' do
        challenges = []

        (1..3).each do |_i|
          challenges.push(Triauth.ping({ identifier: identifier, callbackUrl: callback_url, sessionKey: session_key })[:challenge])
        end

        assert_equal challenges.length, challenges.uniq.length # `(new Set(challenges)).size`
      end

      it 'returns validation error for invalid identifiers' do
        invalid_identifiers = IDENTIFIERS_FIXTURE['invalidIdentifiers']
        invalid_identifiers.each_key do |invalid_identifier|
          ping_res = Triauth.ping({ identifier: invalid_identifier, callbackUrl: callback_url, sessionKey: session_key })
          refute ping_res[:pinged], invalid_identifier
          assert_equal 'invalid_identifier', ping_res[:error][:code], invalid_identifier
        end
      end

      it 'returns validation error for invalid callbackUrls' do
        invalid_urls = ['=', '', "https://[::1]/#{'a' * 1100}"]

        invalid_urls.each do |invalid_url|
          ping_res = Triauth.ping({ identifier: identifier, callbackUrl: invalid_url, sessionKey: session_key })
          refute ping_res[:pinged]
          assert_equal 'invalid_callback_url', ping_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_arguments}} for unrecognized options' do
        ping_res = Triauth.ping({ identifier: identifier, callbackUrl: callback_url, sessionKey: session_key, unknownKey: 1 })
        refute ping_res[:pinged]
        assert_equal 'invalid_arguments', ping_res[:error][:code]
      end

      it 'returns {error:{code:invalid_session_key}} for invalid session keys' do
        invalid_session_keys = ['short', 123, '', 'A' * 42, 'A' * 44, ":#{'a' * 16}", "#{'A' * 42}+", "#{'A' * 42}B",
                                ":#{'A' * 43}", "Issuer.Example:#{'A' * 43}", "not_a_domain:#{'A' * 43}", "a.example:b.example:#{'A' * 43}",
                                "#{'a' * 254}:#{'A' * 43}", ':' * (8 * 1024 * 1024)]
        invalid_session_keys.each do |invalid_session_key|
          ping_res = Triauth.ping({ identifier: identifier, callbackUrl: callback_url, sessionKey: invalid_session_key })
          refute ping_res[:pinged]
          assert_equal 'invalid_session_key', ping_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_ext}} for malformed ext' do
        invalid_exts = [[], { a: { b: { c: 1 } } }, { x: 'y' * 4096 }]
        invalid_exts.each do |invalid_ext|
          ping_res = Triauth.ping({ identifier: identifier, callbackUrl: callback_url, sessionKey: session_key, ext: invalid_ext })
          refute ping_res[:pinged]
          assert_equal 'invalid_ext', ping_res[:error][:code]
        end
      end
    end

    describe 'session key routing and request sealing' do
      # The redirect fragment is `skid=<skid>&request=<iv>.<ciphertext>`. The request opens under the session key
      # to the challenge, and the session key itself never travels.
      # (`new URLSearchParams(redirectUrl.split('#?')[1])`: the fragment's pairs as a Hash of Strings)
      fragment = ->(redirect_url) { URI.decode_www_form(redirect_url.split('#?', -1)[1]).to_h }

      key_record = { value: 'key desktop[1/1]:BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 1800, dnssec: true }
      resolver = lambda do |grant = 'include actor@issuer.example scope=any'|
        DnsResolverStub.new(
          {
            'example.org':           { TXT: [{ value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 1800, dnssec: true }] },
            'john._at.example.org':  { TXT: [key_record, { value: grant, ttl: 1800, dnssec: true }] },
            'issuer.example':        { TXT: [{ value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true }] }
          }
        )
      end
      callback_url = 'https://example.com/'
      session_key = AuthenticatorStub::SESSION_KEY

      it "seals the challenge under the session key, and sends it to the identity's own endpoint" do
        ping_res = Triauth.ping({ identifier: 'john@example.org', callbackUrl: callback_url, sessionKey: session_key }, { resolver: resolver.call })

        assert ping_res[:redirectUrl].start_with?('https://local-auth.example.org/ping.html#?')
        assert_equal Triauth::RequestCipher.skid(session_key), fragment.call(ping_res[:redirectUrl])['skid']
        assert_equal AuthenticatorStub.public_challenge(ping_res[:challenge]), Triauth::RequestCipher.open(session_key, fragment.call(ping_res[:redirectUrl])['request'])
      end

      it 'sends a delegated session key `<domain>:<key>` to the authenticator of that domain' do
        ping_res = Triauth.ping({ identifier: 'john@example.org', callbackUrl: callback_url, sessionKey: "issuer.example:#{session_key}" }, { resolver: resolver.call })

        assert ping_res[:redirectUrl].start_with?('https://remote-auth.issuer.example/ping.html#?')
        assert_equal AuthenticatorStub.public_challenge(ping_res[:challenge]), Triauth::RequestCipher.open(session_key, fragment.call(ping_res[:redirectUrl])['request'])
      end

      it 'rejects (invalid_session_key) a session key in the `issuer:secret` form of a token' do
        ping_res = Triauth.ping({ identifier: 'john@example.org', callbackUrl: callback_url, sessionKey: "issuer.example:#{'a' * 16}" }, { resolver: resolver.call })

        refute ping_res[:pinged]
        assert_equal 'invalid_session_key', ping_res[:error][:code]
      end

      it 'rejects (invalid_session_key) a session key with a character outside the base64url alphabet' do
        ping_res = Triauth.ping({ identifier: 'john@example.org', callbackUrl: callback_url, sessionKey: "#{'A' * 42}/" }, { resolver: resolver.call })

        refute ping_res[:pinged]
        assert_equal 'invalid_session_key', ping_res[:error][:code]
      end
    end

    describe 'accepts challenge and response to produce ping result' do
      it 'correctly sets the pinged status' do
        callback_url = 'https://example.com/'
        IDENTITIES.each_value do |identity|
          challenge = Triauth.ping({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]

          identity[:devices].each do |device|
            ts_before = Triauth::Helpers.date_now
            response = Triauth::Signature.generate(
              SignerStub.sign_using_device_keys(device[:keys]),
              'ping',
              identity[:identifier], '',
              callback_url,
              AuthenticatorStub.public_challenge(challenge)
            )

            ping_res = Triauth.ping({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
            ts_after = Triauth::Helpers.date_now

            assert_equal true, ping_res[:pinged]
            assert_equal identity[:identifier], ping_res[:identifier]
            assert_equal identity[:identityDomain], ping_res[:identityDomain]
            assert_equal '', ping_res[:actorIdentityDomain]
            assert_equal '', ping_res[:lookupCode]
            assert_equal '', ping_res[:actorLookupCode]
            assert_equal device[:deviceName], ping_res[:deviceName]
            assert_equal true, ping_res[:secure]
            assert ping_res[:expires] > Triauth::Helpers.date_now
            assert_equal device[:keys].length, ping_res[:keys].length
            assert_equal(true, ping_res[:keys].all? { |k| k[:verified] })
            assert ping_res[:signedAt].between?(ts_before, ts_after) # `signedAt >= tsBefore && signedAt <= tsAfter`
            assert ping_res[:issuedAt].is_a?(Integer) && ping_res[:issuedAt] <= ping_res[:signedAt] # `typeof === 'number'`: timestamps are Integers here
            assert ping_res[:verifiedAt].between?(ts_before, ts_after) # `verifiedAt >= tsBefore && verifiedAt <= tsAfter`
            assert ping_res[:signedAt] <= ping_res[:verifiedAt]

            # Invalid signature must not ping
            ping_res_invalid = Triauth.ping({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response.sub('@', '@a')) })
            refute ping_res_invalid[:pinged]
          end
        end
      end

      it 'does not ping expired challenges' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        build_res = Triauth.ping({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:iat] = Triauth::Helpers.date_now - (Triauth.config[:pingTimeout] + 10_000)
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'ping',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(modified_challenge)
        )

        ping_res = Triauth.ping({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute ping_res[:pinged]
        assert_equal 'request_expired', ping_res[:error][:code]
      end

      it 'does not ping challenges with issued at (iat) in future' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        build_res = Triauth.ping({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:iat] = 99_999_999_999_999
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'ping',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(modified_challenge)
        )

        ping_res = Triauth.ping({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute ping_res[:pinged]
        assert_equal 'request_expired', ping_res[:error][:code]
      end

      it 'rejects responses whose envelope `type` is not `ping`' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        challenge = Triauth.ping({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'auth',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )

        ping_res = Triauth.ping({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute ping_res[:pinged]
        assert ping_res[:error]
      end

      it 'rejects challenges whose embedded `type` does not match the ping flow' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        build_res = Triauth.ping({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:type] = 'auth'
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'ping',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(modified_challenge)
        )

        ping_res = Triauth.ping({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute ping_res[:pinged]
        assert_equal 'verification_failed', ping_res[:error][:code]
      end

      it 'verifies identifier, if passed, is the same as in challenge' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        challenge = Triauth.ping({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'ping',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )

        ping_res = Triauth.ping({ identifier: identity[:identifier], challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, ping_res[:pinged]

        ping_res = Triauth.ping({ identifier: 'other-user@example.com', challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute ping_res[:pinged]
        assert_equal 'verification_failed', ping_res[:error][:code]
      end

      it 'verifies callbackUrl, if passed, is the same as in challenge' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        challenge = Triauth.ping({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'ping',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )

        ping_res = Triauth.ping({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response), callbackUrl: callback_url })
        assert_equal true, ping_res[:pinged]

        ping_res = Triauth.ping({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response), callbackUrl: 'https://other-domain.com/' })
        refute ping_res[:pinged]
        assert_equal 'verification_failed', ping_res[:error][:code]
      end

      it 'rejects responses whose signed `via` is not a prefix of the challenge `cburl`' do
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/triauth-callback'

        challenge = Triauth.ping({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'ping',
          identity[:identifier], '',
          'https://attacker.example/',
          AuthenticatorStub.public_challenge(challenge)
        )

        ping_res = Triauth.ping({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute ping_res[:pinged]
      end

      it 'does NOT prevent in-window replay (caller is responsible for invalidating challenges)' do
        # Mirrors the equivalent contract test for Triauth.authenticate.
        identity = IDENTITIES[:john]
        device = identity[:devices][0]
        callback_url = 'https://example.com/'

        challenge = Triauth.ping({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'ping',
          identity[:identifier], '',
          callback_url,
          AuthenticatorStub.public_challenge(challenge)
        )

        first = Triauth.ping({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, first[:pinged]

        second = Triauth.ping({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, second[:pinged], 'library does not track consumed challenges — caller must'
      end

      # The next two tests are `(done)`-style in triauth-js, where the `.catch(() => assert(false))` inside
      # `Promise.allSettled` swallows the assertion; here every value is asserted (an escaping exception fails the test).
      # `void 0` is the key left out, `null` is nil, the rest are the literals.
      it 'does not ping invalid challenges' do
        response = '|ping;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|'

        ping_res = Triauth.ping({ response: response })
        refute ping_res[:pinged], 'void 0'
        [nil, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ'].each do |invalid_challenge|
          ping_res = Triauth.ping({ challenge: invalid_challenge, response: response })
          refute ping_res[:pinged], invalid_challenge.inspect
        end
      end

      it 'does not ping invalid responses' do
        challenge = 'eyJ0eXBlIjoicGluZyIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoid3RyNkpWWEZVWkpCSlVMdGkzYVlabzVBIiwiaWF0IjoxNzM3NzExMDQ1NDY1LCJ2ZXIiOjF9'

        ping_res = Triauth.ping({ challenge: challenge })
        refute ping_res[:pinged], 'void 0'
        [nil, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ'].each do |invalid_response|
          ping_res = Triauth.ping({ challenge: challenge, response: invalid_response })
          refute ping_res[:pinged], invalid_response.inspect
        end
      end
    end
  end

  describe 'Triauth.check' do
    it 'returns {valid:true} for a valid device tag' do
      identity = IDENTITIES[:john]
      check_result = Triauth.check({ identifier: identity[:identifier], deviceTag: identity[:devices][0][:deviceTag] })

      assert_equal true, check_result[:valid]
      refute check_result.key?(:checked)
    end

    it "carries the identity's current groups and reflects membership changes on re-check" do
      zone = lambda do |groups_records|
        DnsResolverStub.new(
          {
            'example.org': { TXT: [{ value: 'triauth local-auth.example.org mode=public', ttl: 1800, dnssec: true }] },
            'member._at.example.org': {
              TXT: [
                { value: "key desktop[1/1]:#{IDENTITIES[:john][:devices][0][:keys][0][:public]}", ttl: 1800, dnssec: true },
                *groups_records.map { |value| { value: value, ttl: 1800, dnssec: true } }
              ]
            }
          }
        )
      end

      device_tag = Triauth.whois({ identifier: 'member@example.org' }, { resolver: zone.call([]) })[:devices][0][:deviceTag]

      before = Triauth.check({ identifier: 'member@example.org', deviceTag: device_tag }, { resolver: zone.call(['groups admins,project3']) })
      assert_equal true, before[:valid]
      assert_equal ['admins@example.org', 'project3@example.org'], before[:groups]

      # The org removes one membership - the next periodic check returns the fresh list for the same device
      after = Triauth.check({ identifier: 'member@example.org', deviceTag: device_tag }, { resolver: zone.call(['groups project3']) })
      assert_equal true, after[:valid]
      assert_equal ['project3@example.org'], after[:groups], 'session-cached groups must be replaced with this fresh list'

      # Failure shapes stay groups-free
      revoked = Triauth.check({ identifier: 'member@example.org', deviceTag: 'not-a-real-tag' }, { resolver: zone.call([]) })
      assert_equal false, revoked[:valid]
      refute revoked.key?(:groups)
    end

    it "returns {valid:false, reason:'revoked'} for invalid or missing device tags" do
      check_result = Triauth.check({ identifier: 'john@triauthdemo.org', deviceTag: 'invalid-tag' })

      assert_equal false, check_result[:valid]
      assert_equal 'revoked', check_result[:reason]
    end

    it 'reports a deviceTag outside the closed grammar as revoked, ahead of any DNS lookup' do
      resolver = DnsResolverStub.new({ 'triauthdemo.org': { _error: 'the DNS must not be queried' } })
      tag = '3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ'

      ["#{tag}~K7QJ3FB9M2WZX0C4~junk", "#{tag}~not-a-lookup-code", "#{tag}:#{tag}", ':' * (8 * 1024 * 1024)].each do |device_tag|
        check_result = Triauth.check({ identifier: 'john@triauthdemo.org', deviceTag: device_tag }, { resolver: resolver })
        assert_equal({ valid: false, reason: 'revoked' }, check_result, device_tag[0, 80])
      end
    end

    it "returns {valid:false, reason:'unresolved'} for identifiers with no identity records" do
      empty_identifiers = IDENTIFIERS_FIXTURE['emptyIdentifiers'] # `invalidIdentifiers` is destructured and unused in triauth-js

      empty_identifiers.each do |empty_identifier|
        check_result = Triauth.check({ identifier: empty_identifier, deviceTag: 'VpGPcGr5psnmgaq4mPxY5tZ4Adxa5V2Vh1GFVRfQFmk' })

        assert_equal false, check_result[:valid]
        assert_equal 'unresolved', check_result[:reason]
      end
    end

    it 'returns {error:{code, message} for invalid identifiers' do
      invalid_identifiers = IDENTIFIERS_FIXTURE['invalidIdentifiers'] # `emptyIdentifiers` is destructured and unused in triauth-js

      invalid_identifiers.each_key do |invalid_identifier|
        check_result = Triauth.check({ identifier: invalid_identifier, deviceTag: 'VpGPcGr5psnmgaq4mPxY5tZ4Adxa5V2Vh1GFVRfQFmk' })

        refute check_result.key?(:checked)
        refute check_result.key?(:valid)
        assert check_result[:error]
      end
    end

    it 'returns {error:{code:invalid_arguments}} for invalid arguments' do
      check_result = Triauth.check({ identifier: {}, deviceTag: {} })

      refute check_result.key?(:checked)
      refute check_result.key?(:valid)
      assert_equal 'invalid_arguments', check_result[:error][:code]
    end

    it 'returns {error:{code:invalid_arguments}} for unrecognized arguments' do
      check_result = Triauth.check({ identifier: 'john@triauthdemo.org', deviceTag: 'VpGPcGr5psnmgaq4mPxY5tZ4Adxa5V2Vh1GFVRfQFmk', unknown: 'value' })

      refute check_result.key?(:checked)
      refute check_result.key?(:valid)
      assert_equal 'invalid_arguments', check_result[:error][:code]
    end

    it 'returns {error:{code:dns_unavailable}} for DNSSEC-failed domains' do
      check_result = Triauth.check({ identifier: 'a@dnssec-failed.org', deviceTag: 'VpGPcGr5psnmgaq4mPxY5tZ4Adxa5V2Vh1GFVRfQFmk' })
      assert_equal 'dns_unavailable', check_result[:error][:code]
    end

    it 'includes secure (boolean) and expires (future timestamp) in a valid check result' do
      identity = IDENTITIES[:john]
      check_result = Triauth.check({ identifier: identity[:identifier], deviceTag: identity[:devices][0][:deviceTag] })

      assert_equal true, check_result[:valid]
      refute check_result.key?(:checked)
      assert check_result[:secure] == true || check_result[:secure] == false # `typeof === 'boolean'`
      assert check_result[:expires].is_a?(Integer) && check_result[:expires] > Triauth::Helpers.date_now # `typeof === 'number'`
    end

    it "bounds expires by the endpoint record TTL when it is shorter than the key records'" do
      identity = IDENTITIES[:john]
      resolver = DnsResolverStub.new(
        {
          'triauthdemo.org': { TXT: [{ value: 'triauth auth.triauthdemo.org mode=public', ttl: 60, dnssec: true }] },
          'john._at.triauthdemo.org': { TXT: [{ value: "key desktop[1/1]:#{identity[:devices][0][:keys][0][:public]}", ttl: 86_400, dnssec: true }] }
        }
      )
      before = Triauth::Helpers.date_now
      check_result = Triauth.check({ identifier: identity[:identifier], deviceTag: identity[:devices][0][:deviceTag] }, { resolver: resolver })

      assert_equal true, check_result[:valid]
      assert check_result[:expires].between?(before + 60_000, Triauth::Helpers.date_now + 60_000), 'the endpoint record expires first' # `expires >= before + 60_000 && expires <= Date.now() + 60_000`
    end

    it "bounds a composite tag's expires by the actor endpoint record TTL" do
      subject_device = IDENTITIES[:john][:devices][0]
      actor_device = IDENTITIES[:john][:devices][1]
      resolver = DnsResolverStub.new(
        {
          'example.org': { TXT: [{ value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 86_400, dnssec: true }] },
          'john._at.example.org': {
            TXT: [
              { value: "key desktop[1/1]:#{subject_device[:keys][0][:public]}", ttl: 86_400, dnssec: true },
              { value: 'include actor@issuer.example scope=any', ttl: 86_400, dnssec: true }
            ]
          },
          'issuer.example': { TXT: [{ value: 'triauth remote-auth.issuer.example mode=public', ttl: 60, dnssec: true }] },
          'actor._at.issuer.example': { TXT: [{ value: "key remote[1/1]:#{actor_device[:keys][0][:public]}", ttl: 86_400, dnssec: true }] }
        }
      )
      subject = Triauth.whois({ identifier: 'john@example.org' }, { resolver: resolver })
      actor = Triauth.whois({ identifier: 'actor@issuer.example' }, { resolver: resolver })
      device_tag = "#{subject[:includes][0][:tag]}:actor@issuer.example:#{actor[:devices][0][:deviceTag]}"
      before = Triauth::Helpers.date_now
      check_result = Triauth.check({ identifier: 'john@example.org', deviceTag: device_tag }, { resolver: resolver })

      assert_equal true, check_result[:valid]
      assert check_result[:expires].between?(before + 60_000, Triauth::Helpers.date_now + 60_000), 'the actor endpoint record expires first' # `expires >= before + 60_000 && expires <= Date.now() + 60_000`
    end

    describe 'delegated deviceTags (composite includeTag:actor:actorDeviceTag)' do
      subject_device = IDENTITIES[:john][:devices][0]
      actor_device   = IDENTITIES[:john][:devices][1]

      # (`({includeRecords, actorZones = true}) =>`: keyword parameters; `...(actorZones ? {...} : {})` is a `merge` of the same)
      zones = lambda do |include_records:, actor_zones: true|
        DnsResolverStub.new(
          {
            'example.org': { TXT: [{ value: 'triauth local-auth.example.org include=issuer.example mode=public', ttl: 1800, dnssec: true }] },
            'john._at.example.org': {
              TXT: [
                { value: "key desktop[1/1]:#{subject_device[:keys][0][:public]}", ttl: 1800, dnssec: true },
                *include_records
              ]
            }
          }.merge(
            if actor_zones
              {
                'issuer.example': { TXT: [{ value: 'triauth remote-auth.issuer.example mode=public', ttl: 1800, dnssec: true }] },
                'actor._at.issuer.example': { TXT: [{ value: "key remote[1/1]:#{actor_device[:keys][0][:public]}", ttl: 1800, dnssec: true }] }
              }
            else
              {}
            end
          )
        )
      end

      grant = { value: 'include actor@issuer.example use=sign scope=any', ttl: 1800, dnssec: true }

      # The composite deviceTag as a delegated authentication would have produced it
      minted_device_tag = lambda do |resolver|
        subject = Triauth::Identity.new('john@example.org', {}, { resolver: resolver })
        actor = Triauth::Identity.new('actor@issuer.example', {}, { resolver: resolver })
        # `Promise.all([subject.resolve(), actor.resolve()])`: the two resolutions in sequence
        subject.resolve
        actor.resolve
        return "#{subject.includes.includes[0][:tag]}:actor@issuer.example:#{actor.keys.key_groups.values[0][:tag]}" # `Object.values(actor.keys.keyGroups)[0].tag`
      end

      it 'is a liveness check: a grant stays valid for its whole lifetime regardless of its use option' do
        resolver = zones.call(include_records: [grant])
        device_tag = minted_device_tag.call(resolver)

        # The grant covers only `sign`, yet check (which carries no flow) accepts it
        check_result = Triauth.check({ identifier: 'john@example.org', deviceTag: device_tag }, { resolver: zones.call(include_records: [grant]) })
        assert_equal true, check_result[:valid]
        assert check_result[:secure] == true || check_result[:secure] == false # `typeof === 'boolean'`
        assert check_result[:expires].is_a?(Integer) && check_result[:expires] > Triauth::Helpers.date_now # `typeof === 'number'`
      end

      it 'reports revoked when the include record is gone, or when the pinned grant/actor device no longer matches' do
        device_tag = minted_device_tag.call(zones.call(include_records: [grant]))

        gone = Triauth.check({ identifier: 'john@example.org', deviceTag: device_tag }, { resolver: zones.call(include_records: []) })
        assert_equal({ valid: false, reason: 'revoked' }, gone)

        _, actor_identifier, actor_device_tag = device_tag.split(':', -1)
        other_grant = Triauth.check(
          { identifier: 'john@example.org', deviceTag: "#{'A' * 43}:#{actor_identifier}:#{actor_device_tag}" },
          { resolver: zones.call(include_records: [grant]) }
        )
        assert_equal({ valid: false, reason: 'revoked' }, other_grant)

        other_device = Triauth.check(
          { identifier: 'john@example.org', deviceTag: device_tag.sub(/[^:]+\z/, 'B' * 43) },
          { resolver: zones.call(include_records: [grant]) }
        )
        assert_equal({ valid: false, reason: 'revoked' }, other_device)
      end

      it 'reports unresolved when the actor identity cannot be resolved (distinct from revocation)' do
        device_tag = minted_device_tag.call(zones.call(include_records: [grant]))

        check_result = Triauth.check(
          { identifier: 'john@example.org', deviceTag: device_tag },
          { resolver: zones.call(include_records: [grant], actor_zones: false) }
        )
        assert_equal({ valid: false, reason: 'unresolved' }, check_result)
      end

      it 'is scope-blind: a grant scoped to another service stays valid - check carries no flow and no callback URL' do
        scoped_grant = { value: 'include actor@issuer.example use=sign scope=other.example', ttl: 1800, dnssec: true }
        device_tag = minted_device_tag.call(zones.call(include_records: [scoped_grant]))

        check_result = Triauth.check({ identifier: 'john@example.org', deviceTag: device_tag }, { resolver: zones.call(include_records: [scoped_grant]) })
        assert_equal true, check_result[:valid]
      end

      it 'SECURITY: reports revoked for a deviceTag pinned to the scope=any grant when the published grant carries a host list - scope folds into the grant tag' do
        device_tag = minted_device_tag.call(zones.call(include_records: [grant]))
        scoped_grant = { value: 'include actor@issuer.example use=sign scope=example.com', ttl: 1800, dnssec: true }

        check_result = Triauth.check({ identifier: 'john@example.org', deviceTag: device_tag }, { resolver: zones.call(include_records: [scoped_grant]) })
        assert_equal({ valid: false, reason: 'revoked' }, check_result)
      end

      it 'SECURITY: reports revoked for a deviceTag pinned to the scope=any grant when the published grant lacks scope - the record is ignored as a whole' do
        device_tag = minted_device_tag.call(zones.call(include_records: [grant]))
        scopeless_record = { value: 'include actor@issuer.example use=sign', ttl: 1800, dnssec: true }

        check_result = Triauth.check({ identifier: 'john@example.org', deviceTag: device_tag }, { resolver: zones.call(include_records: [scopeless_record]) })
        assert_equal({ valid: false, reason: 'revoked' }, check_result)
      end

      it 'reports revoked for malformed composite deviceTags' do
        resolver = -> { zones.call(include_records: [grant]) }
        tag = 'C' * 43

        [
          "#{tag}:#{tag}",                                  # two segments
          "#{tag}:actor@issuer.example:#{tag}:#{tag}",      # four segments
          "#{tag}:Actor@Issuer.example:#{tag}",             # non-lowercase actor identifier
          ":actor@issuer.example:#{tag}",                   # empty include tag
          "#{tag}:actor@issuer.example:"                    # empty actor device tag
        ].each do |malformed|
          check_result = Triauth.check({ identifier: 'john@example.org', deviceTag: malformed }, { resolver: resolver.call })
          assert_equal({ valid: false, reason: 'revoked' }, check_result, malformed)
        end
      end
    end

    it 'returns error dnssec_required when config.requireSecure is set and the device keys are not DNSSEC-secure' do
      identity = IDENTITIES[:john]
      device = identity[:devices][0]

      key_records = lambda do |dnssec|
        device[:keys].each_with_index.map do |key, idx|
          {
            value: "key #{device[:deviceName]}[#{idx + 1}/#{device[:keys].length}]:#{key[:public]} type=es256",
            ttl: 1800,
            dnssec: dnssec
          }
        end
      end

      [true, false].each do |secure|
        resolver = DnsResolverStub.new(
          {
            'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=public'] },
            'john._at.triauthdemo.org': { TXT: key_records.call(secure) }
          }
        )

        # Default (requireSecure off): valid regardless of `secure`.
        # (`def` is a keyword in Ruby, so the JS `def` reads `default`)
        default = Triauth.check({ identifier: identity[:identifier], deviceTag: device[:deviceTag] }, { resolver: resolver })
        assert_equal true, default[:valid]
        refute default.key?(:checked)
        assert_equal secure, default[:secure]

        # requireSecure on: DNSSEC-secure keys stay valid; non-secure keys are rejected with dnssec_required.
        strict = Triauth.check({ identifier: identity[:identifier], deviceTag: device[:deviceTag] }, { resolver: resolver, requireSecure: true })
        if secure
          assert_equal true, strict[:valid]
          assert_equal true, strict[:secure]
        else
          refute strict.key?(:valid), 'non-DNSSEC check must not return a valid verdict under requireSecure'
          assert_equal 'dnssec_required', strict[:error][:code]
          assert_equal 'Your domain does not support DNSSEC, which is required to continue.', strict[:error][:message]
        end
      end
    end

    it 'does not gate the revoked (valid:false) path on requireSecure' do
      # Keys exist but the queried deviceTag does not match -> {valid:false}; requireSecure must not turn this into dnssec_required.
      identity = IDENTITIES[:john]
      device = identity[:devices][0]
      resolver = DnsResolverStub.new(
        {
          'triauthdemo.org': { TXT: ['triauth auth.triauthdemo.org mode=public'] },
          'john._at.triauthdemo.org': { TXT: device[:keys].each_with_index.map { |key, idx| "key #{device[:deviceName]}[#{idx + 1}/#{device[:keys].length}]:#{key[:public]} type=es256" } }
        }
      )

      res = Triauth.check({ identifier: identity[:identifier], deviceTag: 'nonexistent-device-tag' }, { resolver: resolver, requireSecure: true })
      assert_equal false, res[:valid]
      assert_equal 'revoked', res[:reason]
      refute res[:error], 'revoked path must not surface an error under requireSecure'
    end
  end

  # port-only: a missing options argument is the JS `undefined`, which the flow's `perform(type, options = {}, ...)` default
  # turns into `{}` (invalid_arguments with the flow's message), while an explicit nil is the JS `null` (invalid_arguments from the
  # known-keys guard); `check` has no such default on either side
  it 'answers invalid_arguments for authenticate() and ping() without an argument, as the flow default does for undefined in triauth-js, and invalid_arguments for an explicit nil (the JS null)' do
    flow_message = 'Invalid or missing function arguments - expected either {identifier,callbackUrl,ext,...} or {challenge,response,identifier?,callbackUrl?}'
    # the top-level aliases `Triauth.authenticate` and `Triauth.ping` forward the same default (hazards pass, lib/triauth.rb)
    [Triauth::Api::Authentication.authenticate, Triauth::Api::Authentication.ping, Triauth.authenticate, Triauth.ping].each do |res|
      assert_equal 'invalid_arguments', res[:error][:code]
      assert_equal flow_message, res[:error][:message]
    end
    [
      Triauth::Api::Authentication.authenticate(nil), Triauth::Api::Authentication.ping(nil), Triauth::Api::Authentication.check, Triauth::Api::Authentication.check(nil),
      Triauth.authenticate(nil), Triauth.ping(nil), Triauth.check, Triauth.check(nil)
    ].each do |res|
      assert_equal 'invalid_arguments', res[:error][:code]
      assert_equal 'Unrecognized function argument', res[:error][:message]
    end
  end
end
