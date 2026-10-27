# frozen_string_literal: true

require_relative 'setup'
require_relative 'stubs/signer'
require_relative 'stubs/authenticator'
require_relative 'stubs/dns_resolver'
# The demo zone, served from the fixture: the suites resolve through it, as the triauth-js run does through test_unit.js
require_relative 'stubs/zone_resolver'
require 'json'

# The identities fixture with Symbol keys (the data keys of the devices and their JWKs).
# (guarded like the zone stub, so that test.rb and a standalone run load it once; shared with the other API suites)
IDENTITIES = JSON.parse(File.read(File.expand_path('fixtures/identities.json', __dir__)), symbolize_names: true) unless defined?(IDENTITIES)
# The identifiers fixture is read with String keys: the keys of `invalidIdentifiers` are identifier values, not property names.
# (guarded like the zone stub, so that test.rb and a standalone run load it once; shared with test_identity.rb and test_validation.rb)
IDENTIFIERS_FIXTURE = JSON.parse(File.read(File.expand_path('fixtures/identifiers.json', __dir__))) unless defined?(IDENTIFIERS_FIXTURE)

describe 'Signing API' do
  describe 'Triauth.sign' do
    it 'builds a challenge for an identifier that publishes no records - existence is settled at stage 3' do
      sign_res = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: 'john-missing@triauthdemo.org', callbackUrl: 'http://localhost/', message: 'Test' })

      refute sign_res[:error]
      assert !sign_res[:challenge].nil? && !sign_res[:challenge].empty? # `assert(signRes.challenge)`: the JS falsy set of a string
    end

    describe 'accepts identifier, callbackUrl, message, and sessionKey to produce challenge and redirectUrl' do
      identifier = 'john@triauthdemo.org'
      callback_url = 'https://example.com/'
      message = 'Please sign this'
      session_key = AuthenticatorStub::SESSION_KEY
      attachments = [{
        name: 'License.txt',
        sourceUrl: 'https://example.com/license.txt',
        sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
      }]

      it 'returns challenge and a correct redirectUrl for valid input' do
        sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key })
        assert sign_res[:challenge].is_a?(String) && sign_res[:challenge].length > 0
        assert sign_res[:redirectUrl].is_a?(String) && sign_res[:redirectUrl].length > 0
      end

      it 'encodes type, identifier, callbackUrl, and message in the challenge' do
        sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key })
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(sign_res[:challenge]))

        assert_equal 'sign', challenge_request.data[:type]
        assert_equal identifier, challenge_request.data[:identifier]
        assert_equal callback_url, challenge_request.data[:cburl]
        assert_equal message, challenge_request.data[:msg]
        assert_equal 1, challenge_request.data[:ver]
      end

      # `|; x|` makes `x` local to its block: the JS `const message` below shadows the outer one of the same name, where a
      # plain assignment inside a Ruby block would reassign the outer local.
      it 'encodes a message with non-latin-1 characters in the challenge' do |; message| # rubocop:disable Layout/SpaceAroundBlockParameters -- block-local variables only, no parameter: the cop misreads `|; x|`
        # Regression: btoa()-based encoding used to throw on chars > U+00FF and surface as an internal error (internal_error)
        message = 'Привет, мир'
        sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key })

        assert_nil sign_res[:error], sign_res[:error].inspect
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(sign_res[:challenge]))
        assert_equal message, challenge_request.data[:msg]
      end

      it 'seals the challenge into redirectUrl under the session key, next to its skid' do
        sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key })
        assert sign_res[:redirectUrl].include?('#?skid=') && sign_res[:redirectUrl].include?('&request=')
        assert !sign_res[:redirectUrl].include?('challenge=') && !sign_res[:redirectUrl].include?('token=')
      end

      it 'rejects a request without a session key with invalid_session_key - sign follows a sign-in' do
        sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message })
        assert_equal 'invalid_session_key', sign_res.dig(:error, :code)
      end

      it 'accepts optional attachments and encodes them in the challenge' do
        sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key, attachments: attachments })
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(sign_res[:challenge]))

        assert_equal attachments, challenge_request.data[:attachments]
      end

      it 'generates random and unique challenges for each call' do
        challenges = []

        (1..3).each do |_i|
          challenges.push(Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key })[:challenge])
        end

        assert_equal challenges.length, challenges.uniq.length
      end

      it 'returns {error:{code:invalid_message}} for invalid messages' do
        invalid_messages = [123, nil, '', "has \n newline", "has \x00 NUL", 'a' * 2050]
        invalid_messages.each do |invalid_message|
          sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: invalid_message, sessionKey: session_key })
          refute sign_res[:signed]
          assert_equal 'invalid_message', sign_res[:error][:code]
        end
      end

      it 'accepts messages up to messageBytesize (regression: must not be capped at the 255-byte isNormalString default)' do
        # messageBytesize is 2048; isNormalString's default cap must not silently shadow it.
        [256, 1024, 2048].each do |n|
          sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: 'a' * n, sessionKey: session_key })
          assert !sign_res[:challenge].nil? && !sign_res[:challenge].empty?, "a #{n}-byte message must be accepted"
          refute sign_res[:error], "a #{n}-byte message must not be rejected"
        end
      end

      it 'returns {error:{code:invalid_attachments}} for malformed attachments' do
        base = attachments[0]
        invalid_attachment_sets = [
          'not-an-array',
          [{ name: base[:name], sourceUrl: base[:sourceUrl] }],                                       # missing sha256
          [{ name: base[:name], sourceUrl: base[:sourceUrl], sha256: 'not-hex' }],                    # malformed sha256
          [{ name: base[:name], sourceUrl: 'https://[::1]/file.txt', sha256: base[:sha256] }],              # IPv6-literal host (out of grammar)
          [{ name: base[:name], sourceUrl: 'https://user:pass@example.com/file', sha256: base[:sha256] }],  # credentials
          [base, base],                                                                                # duplicate name
          [{ name: base[:name], sourceUrl: base[:sourceUrl], sha256: base[:sha256], extra: 'x' }]       # extra property
        ]
        invalid_attachment_sets.each do |invalid_attachments|
          sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key, attachments: invalid_attachments })
          refute sign_res[:signed]
          assert_equal 'invalid_attachments', sign_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_attachments}} for more than attachmentsCount (10) attachments, while accepting exactly 10' do
        # The explicit count cap (LIMITS.attachmentsCount = 10) is a gate distinct from the
        # challengeBytesize byte cap exercised below: these entries are tiny, so the 11th must
        # surface as invalid_attachments (too many), not invalid_challenge (too big).
        make = lambda do |n|
          (0...n).map do |i|
            {
              name: "file-#{i}",
              sourceUrl: "https://example.com/f#{i}.txt",
              sha256: '0' * 64
            }
          end
        end

        ten_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key, attachments: make.call(10) })
        assert !ten_res[:challenge].nil? && !ten_res[:challenge].empty?, 'exactly 10 attachments must be accepted'
        refute ten_res[:error], 'exactly 10 attachments must not be rejected'

        eleven_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key, attachments: make.call(11) })
        refute eleven_res[:signed]
        assert_equal 'invalid_attachments', eleven_res[:error][:code]
      end

      it 'returns {error:{code:invalid_challenge}} when the assembled challenge exceeds challengeBytesize (fails early, before DNS)' do
        # Every input is individually valid, but enough max-length attachment sourceUrls push the
        # serialized challenge past LIMITS.challengeBytesize — the stage-1 guard surfaces this as invalid_challenge.
        big_attachments = (0...8).map do |i|
          {
            name: "file-#{i}",
            sourceUrl: "https://example.com/#{'a' * 2000}",
            sha256: '0' * 64
          }
        end
        sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key, attachments: big_attachments })
        refute sign_res[:signed]
        assert_equal 'invalid_challenge', sign_res[:error][:code]
      end

      it 'returns validation error for invalid identifiers' do
        invalid_identifiers = IDENTIFIERS_FIXTURE['invalidIdentifiers']
        invalid_identifiers.each_key do |invalid_identifier| # `for...in`
          sign_res = Triauth.sign({ identifier: invalid_identifier, callbackUrl: callback_url, message: message, sessionKey: session_key })
          refute sign_res[:signed], invalid_identifier
          assert_equal 'invalid_identifier', sign_res[:error][:code], invalid_identifier
        end
      end

      it 'returns {error:{code:invalid_callback_url}} for invalid callbackUrls' do
        invalid_urls = ['=', '', "https://[::1]/#{'a' * 1100}"]

        invalid_urls.each do |invalid_url|
          sign_res = Triauth.sign({ identifier: identifier, callbackUrl: invalid_url, message: message, sessionKey: session_key })
          refute sign_res[:signed]
          assert_equal 'invalid_callback_url', sign_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_arguments}} for unrecognized options' do
        sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key, unknownKey: 1 })
        refute sign_res[:signed]
        assert_equal 'invalid_arguments', sign_res[:error][:code]
      end

      it 'returns {error:{code:invalid_session_key}} for invalid session keys' do
        invalid_session_keys = ['short', 123, '', 'A' * 42, 'A' * 44, ":#{'a' * 16}", "#{'A' * 42}+", "#{'A' * 42}B",
                                ":#{'A' * 43}", "Issuer.Example:#{'A' * 43}", "not_a_domain:#{'A' * 43}", "a.example:b.example:#{'A' * 43}",
                                "#{'a' * 254}:#{'A' * 43}", ':' * (8 * 1024 * 1024)]
        invalid_session_keys.each do |invalid_session_key|
          sign_res = Triauth.sign({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: invalid_session_key })
          refute sign_res[:signed]
          assert_equal 'invalid_session_key', sign_res[:error][:code]
        end
      end
    end

    describe 'accepts challenge and response to produce signing result' do
      it 'correctly sets the signed status (no attachments)' do
        callback_url = 'https://example.com/'
        message = 'Please sign this'

        IDENTITIES.each_value do |identity|
          challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]

          identity[:devices].each do |device|
            response = Triauth::Signature.generate(
              SignerStub.sign_using_device_keys(device[:keys]),
              'sign',
              identity[:identifier], '',
              callback_url,
              message
            )

            sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })

            assert_equal true, sign_res[:signed]
            assert sign_res[:result].is_a?(String) && sign_res[:result].start_with?('|') && sign_res[:result].end_with?('|')
            assert_equal true, sign_res[:verificationResult][:valid]
            assert_equal 'sign', sign_res[:verificationResult][:type]
            assert_equal identity[:identifier], sign_res[:verificationResult][:identifier]
            assert_equal callback_url, sign_res[:verificationResult][:via]
            assert_equal device[:deviceName], sign_res[:verificationResult][:deviceName]
          end
        end
      end

      it 'correctly handles signatures with attachments' do
        callback_url = 'https://example.com/'
        message = 'Sign with attachment'
        attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }]

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message, attachments: attachments })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message,
          { attachments: attachments }
        )

        sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, sign_res[:signed]
        assert_equal attachments, sign_res[:verificationResult][:signedMetadata][:attachments]

        # Milestone timeline at the top level; top-level signedAt mirrors the nested verificationResult.
        assert sign_res[:signedAt].between?(sign_res[:issuedAt], sign_res[:verifiedAt]) # `issuedAt <= signedAt && signedAt <= verifiedAt` (RuboCop `Style/ComparableBetween`)
        assert_equal sign_res[:verificationResult][:signedAt], sign_res[:signedAt]
      end

      it 'produced signature is independently verifiable with Triauth.verify' do
        callback_url = 'https://example.com/'
        message = 'Independently verifiable'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message
        )

        sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, sign_res[:signed]

        verify_res = Triauth.verify(message, sign_res[:result])
        assert_equal true, verify_res[:valid]
        assert_equal 'sign', verify_res[:type]
        assert_equal identity[:identifier], verify_res[:identifier]

        verify_tampered = Triauth.verify("#{message} (tampered)", sign_res[:result])
        assert_equal false, verify_tampered[:valid]
      end

      it 'honors config.requireSecure: a non-DNSSEC signature is rejected with error dnssec_required' do
        callback_url = 'https://example.com/'
        message = 'requireSecure check'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        signature = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message
        )

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

          # Default (requireSecure off): verifies regardless of `secure`.
          verify_default = Triauth.verify(message, signature, {}, { resolver: resolver })
          assert_equal true, verify_default[:valid], "default config must verify (secure:#{secure})"
          assert_equal secure, verify_default[:secure]

          # requireSecure on: a DNSSEC-secure signature still verifies; a non-secure one is rejected with dnssec_required.
          verify_strict = Triauth.verify(message, signature, {}, { resolver: resolver, requireSecure: true })
          if secure
            assert_equal true, verify_strict[:valid], 'DNSSEC-secure signature must still verify under requireSecure'
            assert_equal true, verify_strict[:secure]
          else
            refute_equal true, verify_strict[:valid], 'non-DNSSEC signature must not verify under requireSecure'
            assert_equal 'dnssec_required', verify_strict[:error][:code]
          end
        end
      end

      it 'rejects response with attachments when challenge requested none' do
        callback_url = 'https://example.com/'
        message = 'No attachments expected'
        sneaky_attachments = [{
          name: 'sneaky.txt',
          sourceUrl: 'https://example.com/sneaky.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }]

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message,
          { attachments: sneaky_attachments }
        )

        sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute sign_res[:signed]
        assert_equal 'verification_failed', sign_res[:error][:code]
      end

      it 'rejects response missing attachments when challenge requested some' do
        callback_url = 'https://example.com/'
        message = 'Attachments expected'
        attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }]

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message, attachments: attachments })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message
        )

        sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute sign_res[:signed]
        assert_equal 'verification_failed', sign_res[:error][:code]
      end

      it 'rejects response with attachment sha256 differing from challenge' do
        callback_url = 'https://example.com/'
        message = 'Mismatched sha'
        attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }]

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message, attachments: attachments })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message,
          { attachments: [{ name: 'License.txt', sourceUrl: attachments[0][:sourceUrl], sha256: '0' * 64 }] }
        )

        sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute sign_res[:signed]
        assert_equal 'verification_failed', sign_res[:error][:code]
      end

      it 'rejects response with mismatched attachment name' do
        callback_url = 'https://example.com/'
        message = 'Mismatched name'
        attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }]

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message, attachments: attachments })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message,
          { attachments: [{ name: 'Other.txt', sourceUrl: attachments[0][:sourceUrl], sha256: attachments[0][:sha256] }] }
        )

        sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute sign_res[:signed]
        assert_equal 'verification_failed', sign_res[:error][:code]
      end

      it 'rejects mismatched embedded challenge `type`' do
        callback_url = 'https://example.com/'
        message = 'Type tamper'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        build_res = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:type] = 'stamp'
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message
        )

        sign_res = Triauth.sign({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute sign_res[:signed]
        assert_equal 'verification_failed', sign_res[:error][:code]
      end

      it 'rejects mismatched envelope `type`' do
        callback_url = 'https://example.com/'
        message = 'Envelope tamper'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'stamp',
          identity[:identifier], '',
          callback_url,
          message
        )

        sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute sign_res[:signed]
        assert_equal 'verification_failed', sign_res[:error][:code]
      end

      it 'verifies identifier, if passed, is the same as in challenge' do
        callback_url = 'https://example.com/'
        message = 'Cross-check identifier'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message
        )

        sign_res = Triauth.sign({ identifier: identity[:identifier], challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, sign_res[:signed]

        sign_res = Triauth.sign({ identifier: 'other-user@example.com', challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute sign_res[:signed]
        assert_equal 'verification_failed', sign_res[:error][:code]
      end

      it 'verifies callbackUrl, if passed, is the same as in challenge' do
        callback_url = 'https://example.com/'
        message = 'Cross-check callbackUrl'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message
        )

        sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response), callbackUrl: callback_url })
        assert_equal true, sign_res[:signed]

        sign_res = Triauth.sign({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response), callbackUrl: 'https://other-domain.com/' })
        refute sign_res[:signed]
        assert_equal 'verification_failed', sign_res[:error][:code]
      end

      it 'honors per-call signTimeout override' do
        callback_url = 'https://example.com/'
        message = 'Timeout override'
        default_timeout = Triauth.config[:signTimeout]

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        build_res = Triauth.sign({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:iat] = Triauth::Helpers.date_now - (default_timeout + 10_000)
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message
        )

        sign_res = Triauth.sign({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute sign_res[:signed]
        assert_equal 'request_expired', sign_res[:error][:code]

        sign_res = Triauth.sign(
          { challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) },
          { signTimeout: (default_timeout * 2) + 60_000 }
        )
        assert_equal true, sign_res[:signed]
      end

      # The JS version maps every call to a promise whose `.catch(() => assert(false))` swallows the assertion failure inside
      # `Promise.allSettled`, so it passes whatever the library returns (RUN/upstream.md item 5). Here each call runs in turn and
      # its result is asserted; an exception escaping any call fails the test. `void 0` is the key left out, `null` is `nil`.
      it 'does not sign invalid challenges or responses' do
        valid_challenge = 'eyJ0eXBlIjoic2lnbiIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoid3RyNkpWWEZVWkpCSlVMdGkzYVlabzVBIiwiaWF0IjoxNzM3NzExMDQ1NDY1LCJ2ZXIiOjF9'
        valid_response = '|sign;john@triauthdemo.org;-;v1;1775555621331;;;oDpTVMNwz9f0Qz16hF2lygsmT2FkiwNMM8e1jRyB-DO1FutX9kcsMCJUsvbfYJpjCgfFatCpNnNhxTlBmYCnqw|'
        invalid_values = [nil, false, true, '', 123, {}, [], '68fhu7fqm5P', 'ZZZ']

        r = Triauth.sign({ response: valid_response }) # `challenge: void 0`
        refute r[:signed]
        invalid_values.each do |invalid_challenge|
          r = Triauth.sign({ challenge: invalid_challenge, response: valid_response })
          refute r[:signed]
        end
        r = Triauth.sign({ challenge: valid_challenge }) # `response: void 0`
        refute r[:signed]
        invalid_values.each do |invalid_response|
          r = Triauth.sign({ challenge: valid_challenge, response: invalid_response })
          refute r[:signed]
        end
      end
    end
  end

  describe 'Triauth.stamp' do
    describe 'accepts identifier, callbackUrl, message, and sessionKey to produce challenge and redirectUrl' do
      identifier = 'john@triauthdemo.org'
      callback_url = 'https://example.com/'
      message = 'example-data-in-textual-format'
      session_key = AuthenticatorStub::SESSION_KEY

      it 'returns challenge and a correct redirectUrl for valid input' do
        stamp_res = Triauth.stamp({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key })
        assert stamp_res[:challenge].is_a?(String) && stamp_res[:challenge].length > 0
        assert stamp_res[:redirectUrl].is_a?(String) && stamp_res[:redirectUrl].length > 0
      end

      it 'encodes type, identifier, callbackUrl, and message in the challenge' do
        stamp_res = Triauth.stamp({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key })
        challenge_request = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(stamp_res[:challenge]))

        assert_equal 'stamp', challenge_request.data[:type]
        assert_equal identifier, challenge_request.data[:identifier]
        assert_equal callback_url, challenge_request.data[:cburl]
        assert_equal message, challenge_request.data[:msg]
      end

      it 'seals the challenge into redirectUrl under the session key, next to its skid' do
        stamp_res = Triauth.stamp({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key })
        assert stamp_res[:redirectUrl].include?('#?skid=') && stamp_res[:redirectUrl].include?('&request=')
        assert !stamp_res[:redirectUrl].include?('challenge=') && !stamp_res[:redirectUrl].include?('token=')
      end

      it 'rejects a request without a session key with invalid_session_key - stamp follows a sign-in' do
        stamp_res = Triauth.stamp({ identifier: identifier, callbackUrl: callback_url, message: message })
        assert_equal 'invalid_session_key', stamp_res.dig(:error, :code)
      end

      it 'rejects the attachments option even when otherwise valid' do
        attachments = [{
          name: 'License.txt',
          sourceUrl: 'https://example.com/license.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }]
        stamp_res = Triauth.stamp({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key, attachments: attachments })
        refute stamp_res[:stamped]
        assert_equal 'invalid_arguments', stamp_res[:error][:code]
      end

      it 'returns {error:{code:invalid_message}} for invalid messages' do
        invalid_messages = [123, nil, '', "has \n newline", 'a' * 2050]
        invalid_messages.each do |invalid_message|
          stamp_res = Triauth.stamp({ identifier: identifier, callbackUrl: callback_url, message: invalid_message, sessionKey: session_key })
          refute stamp_res[:stamped]
          assert_equal 'invalid_message', stamp_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_session_key}} for invalid session keys' do
        invalid_session_keys = ['short', 123, '', 'A' * 42, 'A' * 44, ":#{'a' * 16}", "#{'A' * 42}+", "#{'A' * 42}B",
                                ":#{'A' * 43}", "Issuer.Example:#{'A' * 43}", "not_a_domain:#{'A' * 43}", "a.example:b.example:#{'A' * 43}",
                                "#{'a' * 254}:#{'A' * 43}", ':' * (8 * 1024 * 1024)]
        invalid_session_keys.each do |invalid_session_key|
          stamp_res = Triauth.stamp({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: invalid_session_key })
          refute stamp_res[:stamped]
          assert_equal 'invalid_session_key', stamp_res[:error][:code]
        end
      end

      it 'returns {error:{code:invalid_arguments}} for unrecognized options' do
        stamp_res = Triauth.stamp({ identifier: identifier, callbackUrl: callback_url, message: message, sessionKey: session_key, unknownKey: 1 })
        refute stamp_res[:stamped]
        assert_equal 'invalid_arguments', stamp_res[:error][:code]
      end
    end

    describe 'accepts challenge and response to produce stamping result' do
      it 'correctly sets the stamped status' do
        callback_url = 'https://example.com/'
        message = 'example-data-in-textual-format'

        IDENTITIES.each_value do |identity|
          challenge = Triauth.stamp({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]

          identity[:devices].each do |device|
            response = Triauth::Signature.generate(
              SignerStub.sign_using_device_keys(device[:keys]),
              'stamp',
              identity[:identifier], '',
              callback_url,
              message
            )

            stamp_res = Triauth.stamp({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })

            assert_equal true, stamp_res[:stamped]
            assert stamp_res[:result].is_a?(String) && stamp_res[:result].start_with?('|') && stamp_res[:result].end_with?('|')
            assert_equal true, stamp_res[:verificationResult][:valid]
            assert_equal 'stamp', stamp_res[:verificationResult][:type]
            assert_equal identity[:identifier], stamp_res[:verificationResult][:identifier]
            assert_equal callback_url, stamp_res[:verificationResult][:via]
            assert_equal device[:deviceName], stamp_res[:verificationResult][:deviceName]
            assert_equal true, stamp_res[:verificationResult][:secure]

            assert stamp_res[:signedAt].between?(stamp_res[:issuedAt], stamp_res[:verifiedAt]) # `issuedAt <= signedAt && signedAt <= verifiedAt` (RuboCop `Style/ComparableBetween`)
            assert_equal stamp_res[:verificationResult][:signedAt], stamp_res[:signedAt]
          end
        end
      end

      it 'produced stamp is independently verifiable with Triauth.verify' do
        callback_url = 'https://example.com/'
        message = 'example-data-in-textual-format'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.stamp({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'stamp',
          identity[:identifier], '',
          callback_url,
          message
        )

        stamp_res = Triauth.stamp({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, stamp_res[:stamped]

        verify_res = Triauth.verify(message, stamp_res[:result])
        assert_equal true, verify_res[:valid]
        assert_equal 'stamp', verify_res[:type]
        assert_equal identity[:identifier], verify_res[:identifier]
      end

      it 'rejects stamp response that carries signedMetadata.attachments' do
        callback_url = 'https://example.com/'
        message = 'stamp with attachments not allowed'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.stamp({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'stamp',
          identity[:identifier], '',
          callback_url,
          message,
          { attachments: [{ name: 'sneaky.txt', sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee' }] }
        )

        stamp_res = Triauth.stamp({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute stamp_res[:stamped]
        assert_equal 'verification_failed', stamp_res[:error][:code]
      end

      it 'rejects responses whose envelope `type` is `sign`' do
        callback_url = 'https://example.com/'
        message = 'envelope mismatch'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.stamp({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'sign',
          identity[:identifier], '',
          callback_url,
          message
        )

        stamp_res = Triauth.stamp({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute stamp_res[:stamped]
        assert_equal 'verification_failed', stamp_res[:error][:code]
      end

      it 'rejects challenges whose embedded `type` was tampered to `sign`' do
        callback_url = 'https://example.com/'
        message = 'embedded mismatch'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        build_res = Triauth.stamp({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:type] = 'sign'
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'stamp',
          identity[:identifier], '',
          callback_url,
          message
        )

        stamp_res = Triauth.stamp({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute stamp_res[:stamped]
        assert_equal 'verification_failed', stamp_res[:error][:code]
      end

      it 'does not stamp expired challenges' do
        callback_url = 'https://example.com/'
        message = 'expired'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        build_res = Triauth.stamp({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:iat] = Triauth::Helpers.date_now - (Triauth.config[:stampTimeout] + 10_000)
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'stamp',
          identity[:identifier], '',
          callback_url,
          message
        )

        stamp_res = Triauth.stamp({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute stamp_res[:stamped]
        assert_equal 'request_expired', stamp_res[:error][:code]
      end

      it 'verifies identifier, if passed, is the same as in challenge' do
        callback_url = 'https://example.com/'
        message = 'cross-check identifier'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.stamp({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'stamp',
          identity[:identifier], '',
          callback_url,
          message
        )

        stamp_res = Triauth.stamp({ identifier: identity[:identifier], challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        assert_equal true, stamp_res[:stamped]

        stamp_res = Triauth.stamp({ identifier: 'other-user@example.com', challenge: challenge, response: AuthenticatorStub.seal(challenge, response) })
        refute stamp_res[:stamped]
        assert_equal 'verification_failed', stamp_res[:error][:code]
      end

      it 'verifies callbackUrl, if passed, is the same as in challenge' do
        callback_url = 'https://example.com/'
        message = 'cross-check callbackUrl'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        challenge = Triauth.stamp({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })[:challenge]
        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'stamp',
          identity[:identifier], '',
          callback_url,
          message
        )

        stamp_res = Triauth.stamp({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response), callbackUrl: callback_url })
        assert_equal true, stamp_res[:stamped]

        stamp_res = Triauth.stamp({ challenge: challenge, response: AuthenticatorStub.seal(challenge, response), callbackUrl: 'https://other-domain.com/' })
        refute stamp_res[:stamped]
        assert_equal 'verification_failed', stamp_res[:error][:code]
      end

      it 'rejects stamp challenge that has attachments injected into challenge.data' do
        callback_url = 'https://example.com/'
        message = 'tampered-challenge-test'

        identity = IDENTITIES[:john]
        device = identity[:devices][0]

        build_res = Triauth.stamp({ sessionKey: AuthenticatorStub::SESSION_KEY, identifier: identity[:identifier], callbackUrl: callback_url, message: message })
        challenge_obj = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(build_res[:challenge]))
        challenge_obj.data[:attachments] = [{
          name: 'sneaky.txt',
          sourceUrl: 'https://example.com/sneaky.txt',
          sha256: 'd8a6cc31abc16b6748c7a21f21611f5a1ec33f67d22ca23d7da1c19b95496bee'
        }]
        modified_challenge = AuthenticatorStub.reencode(build_res[:challenge], challenge_obj.data)

        response = Triauth::Signature.generate(
          SignerStub.sign_using_device_keys(device[:keys]),
          'stamp',
          identity[:identifier], '',
          callback_url,
          message
        )

        stamp_res = Triauth.stamp({ challenge: modified_challenge, response: AuthenticatorStub.seal(modified_challenge, response) })
        refute stamp_res[:stamped]
        assert_equal 'invalid_arguments', stamp_res[:error][:code]
      end
    end
  end

  describe 'Triauth.verify' do
    message = 'Test'
    v1_signature = '|stamp;john@triauthdemo.org;;http://localhost:8080/playground/;v1;1778004366970;;;_KUn9Z_qAp_MmSfYx2tIHIdeBWnumtVH8K053Tpxch7dbAwgrh8GysgxVPrUhJco9HJnFA3j-_T5mf5PEXANOw|'

    it 'is able to verify v1 signatures' do
      verify_res = Triauth.verify(message, v1_signature)

      assert_equal true, verify_res[:valid]
      assert_equal 'stamp', verify_res[:type]
      assert_equal 'john@triauthdemo.org', verify_res[:identifier]
      assert_equal 'http://localhost:8080/playground/', verify_res[:via]
      assert_equal 1, verify_res[:ver]
      assert_equal 1_778_004_366_970, verify_res[:signedAt]
      assert Triauth::Helpers.is_number(verify_res[:verifiedAt]) && verify_res[:verifiedAt] >= verify_res[:signedAt]
      refute verify_res.key?(:issuedAt) # verify has no challenge, so no issuedAt milestone
    end

    it 'reports an envelope whose metadata carries lone surrogate escapes as malformed, as the reference does (port-only)' do
      # the reference refuses the surrogate code point such an escape parses to, in the signed and the unsigned slot alike
      # (verify.json pins all three); the source gate refuses the escape here, with the same verdict
      identity = IDENTITIES[:john]
      envelope = lambda do |signed_json, unsigned_json|
        slots = ['stamp', identity[:identifier], '', 'https://example.com/', 'v1', Triauth::Helpers.date_now.to_s, signed_json.nil? ? '' : Triauth::Helpers.string_to_base64url(signed_json), '', message]
        crypto_signatures = SignerStub.from_device_keys(identity[:devices][0][:keys]).sign(slots.join(';'))
        slots[7] = unsigned_json.nil? ? '' : Triauth::Helpers.string_to_base64url(unsigned_json)
        slots[8] = crypto_signatures.join(';')
        "|#{slots.join(';')}|"
      end
      [
        ['{"x":"\\ud800","y":["\\udc00\\ud800",{"z":"\\udfff"}]}', nil], # the signed slot
        [nil, '{"u":"a\\ud800b"}'],                                     # the unsigned slot
        ['{"x":"\\udc00\\ud800"}', nil]                                 # mis-paired, low before high
      ].each do |signed_json, unsigned_json|
        verify_res = Triauth.verify(message, envelope.call(signed_json, unsigned_json))
        assert_equal false, verify_res[:valid], [signed_json, unsigned_json, verify_res].inspect
        assert_equal 'malformed', verify_res[:reason], [signed_json, unsigned_json].inspect
      end
      # a surrogate pair is one code point: the envelope verifies and the metadata carries it
      verify_res = Triauth.verify(message, envelope.call('{"x":"\\ud83d\\ude00"}', nil))
      assert_equal true, verify_res[:valid], verify_res.inspect
      assert_equal({ x: "\u{1F600}" }, verify_res[:signedMetadata])
    end

    it 'returns {valid:false} when signature is invalid or does not meet the constraints' do
      # `let verifyRes;` is not declared: it is assigned below (a nil pre-assignment is `Lint/UselessAssignment`)

      # A valid signature acts as a baseline for next tests
      valid_message = message.dup # `message + ''`: a copy of the string (RuboCop `Style/StringConcatenation`)
      valid_signature = v1_signature.dup # `v1Signature + ''`

      verify_res = Triauth.verify(valid_message, valid_signature)
      assert_equal true, verify_res[:valid] # baseline

      # A modified message should not validate
      verify_res = Triauth.verify("#{valid_message} ", valid_signature)
      assert_equal false, verify_res[:valid]

      # A modified signature should not validate
      verify_res = Triauth.verify(valid_message, valid_signature.sub('E', 'A'))
      assert_equal false, verify_res[:valid]

      # A signature with invalid syntax should not validate
      invalid_signatures = [valid_signature.sub('@', '-'), '', "\n", ' ', '//']
      invalid_signatures.each do |invalid_signature|
        verify_res = Triauth.verify(valid_message, invalid_signature)
        assert_equal false, verify_res[:valid]
        assert_equal 'malformed', verify_res[:reason]
        refute verify_res.key?(:verified)
      end

      # Constraints should be taken into account
      verify_res = Triauth.verify(valid_message, valid_signature, { identifier: 'john@triauthdemo.org' })
      assert_equal true, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { identifier: '-' })
      assert_equal false, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { ver: 1 })
      assert_equal true, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { ver: 2 })
      assert_equal false, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { type: 'stamp' })
      assert_equal true, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { type: 'sign' })
      assert_equal false, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { notBefore: 1_778_004_366_970 })
      assert_equal true, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { notBefore: 1_778_004_366_970 + 1 })
      assert_equal false, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { notAfter: 1_778_004_366_970 })
      assert_equal true, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { notAfter: 1_778_004_366_970 - 1 })
      assert_equal false, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { via: 'http://localhost:8080/playground/' })
      assert_equal true, verify_res[:valid]

      verify_res = Triauth.verify(valid_message, valid_signature, { via: '-' })
      assert_equal false, verify_res[:valid]
    end

    it 'returns {valid:false} when identity does not exist' do
      # `let verifyRes;` is not declared: it is assigned below (a nil pre-assignment is `Lint/UselessAssignment`)

      verify_res = Triauth.verify('Lorem ipsum', '|john@example.invalid;v1;sig;-;1772111038143;kZkVpe-QzTIdn9IyjqDI9ram8AJblrg5AW7T1lo6Xoeiah1NgiUEQPQ3JZyDv8YhoHPkWgV0Qeb7vjW9BB6a4g|')
      assert_equal false, verify_res[:valid], 'Valid should be null for identifiers using unconfigured domains'

      verify_res = Triauth.verify('Lorem ipsum', '|not-existing@triauthdemo.org;v1;sig;-;1772111038143;kZkVpe-QzTIdn9IyjqDI9ram8AJblrg5AW7T1lo6Xoeiah1NgiUEQPQ3JZyDv8YhoHPkWgV0Qeb7vjW9BB6a4g|')
      assert_equal false, verify_res[:valid], 'Valid should be null for identifiers with no identity records in the DNS'

      verify_res = Triauth.verify('Dolor sit', [1])
      assert_nil verify_res[:valid], 'Valid should be undefined when invalid arguments are passed to the function'
      assert_equal 'invalid_arguments', verify_res[:error][:code]
    end

    it 'returns a multi-signature envelope when the input has more than one signature' do |; message| # rubocop:disable Layout/SpaceAroundBlockParameters -- block-local variables only, no parameter: the cop misreads `|; x|`
      # The verify implementation returns the verifyResult itself (with `type:'multisig'`
      # and a `signatures` array) only when signatures.length > 1; for a single signature
      # it returns that signature's shape directly. Build a 2-signature envelope so the
      # multi-signature branch in src/api/signing.js:verify is exercised. Two devices sign, so the
      # segments differ in bytes on every runtime, deterministic (RFC 6979) ECDSA included. Verifying a
      # multi-signature requires opting in with maxSignatures (>= the segment count); by
      # default verify rejects multi-signature envelopes (covered by the test below).
      identity = IDENTITIES[:john]
      device_a, device_b = identity[:devices]
      via = 'https://example.com/'
      message = 'multi-sig-verify-test'

      sig_a = Triauth::Signature.generate(
        SignerStub.sign_using_device_keys(device_a[:keys]),
        'stamp',
        identity[:identifier], '',
        via,
        message
      )
      sig_b = Triauth::Signature.generate(
        SignerStub.sign_using_device_keys(device_b[:keys]),
        'stamp',
        identity[:identifier], '',
        via,
        message
      )
      multi_sig = Triauth::MultiSignature.generate(sig_a, sig_b)

      verify_res = Triauth.verify(message, multi_sig, { maxSignatures: 2 })

      assert_equal true, verify_res[:valid]
      refute verify_res.key?(:verified)
      assert_equal 'multisig', verify_res[:type]
      assert verify_res[:signatures].is_a?(Array)
      assert_equal 2, verify_res[:signatures].length
      assert(verify_res[:signatures].all? { |s| s[:valid] && s[:type] == 'stamp' && s[:identifier] == identity[:identifier] })
    end

    it 'declines an out-of-policy signature count with {valid:false, reason:\'declined\'}' do |; message| # rubocop:disable Layout/SpaceAroundBlockParameters -- block-local variables only, no parameter: the cop misreads `|; x|`
      # A signature-count policy mismatch is reported as {valid:false, reason:'declined'} - no cryptographic verification
      identity = IDENTITIES[:john]
      device_a, device_b = identity[:devices]
      via = 'https://example.com/'
      message = 'multi-sig-default-reject-test'

      sig_a = Triauth::Signature.generate(SignerStub.sign_using_device_keys(device_a[:keys]), 'stamp', identity[:identifier], '', via, message)
      sig_b = Triauth::Signature.generate(SignerStub.sign_using_device_keys(device_b[:keys]), 'stamp', identity[:identifier], '', via, message)
      multi_sig = Triauth::MultiSignature.generate(sig_a, sig_b)

      # Default maxSignatures:1, 2-segment envelope -> declined under the count policy.
      verify_res = Triauth.verify(message, multi_sig)
      assert_equal false, verify_res[:valid]
      assert_equal 'declined', verify_res[:reason]
      refute_equal 'multisig', verify_res[:type]

      # minSignatures alone does not raise the default cap, so it is still declined.
      min_only = Triauth.verify(message, multi_sig, { minSignatures: 2 })
      assert_equal false, min_only[:valid]
      assert_equal 'declined', min_only[:reason]

      # Explicit maxSignatures below the segment count -> also a count-policy decline.
      over_max = Triauth.verify(message, multi_sig, { maxSignatures: 1 })
      assert_equal false, over_max[:valid]
      assert_equal 'declined', over_max[:reason]

      # minSignatures floor not met (even with a sufficient maxSignatures) -> count-policy decline.
      under_min = Triauth.verify(message, multi_sig, { minSignatures: 3, maxSignatures: 5 })
      assert_equal false, under_min[:valid]
      assert_equal 'declined', under_min[:reason]

      # An explicit maxSignatures:0 is a real (zero) bound, not "unset": every envelope has >=1 segment,
      # so it is a count-policy decline -> {valid:false, reason:'declined'} (regression guard for the falsy-0 bug).
      zero_max = Triauth.verify(message, multi_sig, { maxSignatures: 0 })
      assert_equal false, zero_max[:valid]
      assert_equal 'declined', zero_max[:reason]

      # A malformed (non-numeric or NaN) bound is a caller argument error -> {error:{code:invalid_arguments}}, surfaced
      # before any cryptographic work (louder than silently failing the signature closed).
      non_numeric = Triauth.verify(message, multi_sig, { maxSignatures: '1' })
      assert_equal 'invalid_arguments', non_numeric[:error][:code]
      nan_bound = Triauth.verify(message, multi_sig, { minSignatures: Float::NAN })
      assert_equal 'invalid_arguments', nan_bound[:error][:code]

      # Raising maxSignatures to the segment count is what enables multi-signature verification.
      opted_in = Triauth.verify(message, multi_sig, { maxSignatures: 2 })
      assert_equal true, opted_in[:valid]
      refute opted_in.key?(:verified)
      assert_equal 'multisig', opted_in[:type]
    end
  end
end
