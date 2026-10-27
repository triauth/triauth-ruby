# frozen_string_literal: true

require_relative '../setup'
require 'json'
require 'openssl'

module TestInternals
  def self.verifiers
    describe 'Verifiers' do
      describe 'Triauth.Verifiers.Base' do
        # Triauth.Verifiers.Base carries the contract that every verifier implements, and no
        # implementation of its own: a registered class that leaves either member unimplemented
        # names itself in the error, rather than failing as a missing property at the call site.

        it 'rejects the abstract fromPublishableKey - a subclass must implement it' do
          err = assert_raises(RuntimeError) do
            Triauth::Verifiers::Base.from_publishable_key('BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8')
          end
          assert_match(/Triauth\.Verifiers\.Base\.fromPublishableKey is abstract and must be implemented by a subclass/, err.message)
        end

        it 'rejects the abstract verify - a subclass must implement it' do
          err = assert_raises(RuntimeError) do
            Triauth::Verifiers::Base.new.verify('message', 'signature', {}, {})
          end
          assert_match(/Triauth\.Verifiers\.Base#verify is abstract and must be implemented by a subclass/, err.message)
        end
      end

      describe 'P-256 key forms (Ecdsa, WebAuthnEs256)' do
        # An ES256 key record carries the uncompressed (0x04) or the compressed (0x02/0x03) point.
        # Triauth.Helpers.decodeP256PublicKey decodes both on every runtime, so no form depends on
        # what the Web Crypto implementation imports. The hybrid form (0x06/0x07) never imports,
        # also where OpenSSL would accept it (EC_POINT_bn2point does, probe 12).

        message = 'triauth P-256 key forms'
        b64u = ->(bytes) { Triauth::Helpers.array_buffer_to_base64url(bytes) }

        # OpenSSL signs to the DER `SEQUENCE { INTEGER r, INTEGER s }`; the wire carries the raw `r || s`.
        der_to_raw = lambda do |der|
          r, s = OpenSSL::ASN1.decode(der).value.map { |i| i.value.to_s(2) }
          r.rjust(32, "\x00") + s.rjust(32, "\x00")
        end

        # One key pair of each y parity, with its signature over `message`
        # (the `keyPairs` lambda of triauth-js is an instance method here, as it uses the assertions)
        define_method(:key_pairs) do
          by_parity = {}
          i = 0
          while by_parity.size < 2 && i < 64
            key_pair = OpenSSL::PKey::EC.generate('prime256v1')
            raw = key_pair.public_key.to_octet_string(:uncompressed)
            signature = der_to_raw.call(key_pair.sign('SHA256', Triauth::Helpers.string_to_utf8_bytes(message)))
            by_parity[raw.getbyte(64) & 1] = { raw: raw, signature: b64u.call(signature) }
            i += 1
          end
          assert_equal 2, by_parity.size
          by_parity.values
        end

        it 'Ecdsa builds a verifier from the compressed key of either prefix, and it verifies the signatures of the key' do
          key_pairs.each do |pair|
            raw, signature = pair.values_at(:raw, :signature)
            compressed = [0x02 | (raw.getbyte(64) & 1)].pack('C') + raw.byteslice(1, 32)
            verifier = Triauth::Verifiers::Ecdsa.from_publishable_key(b64u.call(compressed))

            assert_kind_of Triauth::Verifiers::Ecdsa, verifier
            assert_equal true, verifier.verify(message, signature, {}, {})

            # The other prefix names the negated point, a different key
            negated = [compressed.getbyte(0) ^ 1].pack('C') + compressed.byteslice(1..)
            assert_equal false, Triauth::Verifiers::Ecdsa.from_publishable_key(b64u.call(negated)).verify(message, signature, {}, {})
          end
        end

        it 'WebAuthnEs256 builds a verifier from the compressed key of either prefix' do
          key_pairs.each do |pair|
            raw = pair[:raw]
            compressed = [0x02 | (raw.getbyte(64) & 1)].pack('C') + raw.byteslice(1, 32)
            assert_kind_of Triauth::Verifiers::WebAuthnEs256, Triauth::Verifiers::WebAuthnEs256.from_publishable_key(b64u.call(compressed))
          end
        end

        it 'Ecdsa and WebAuthnEs256 resolve to null for the hybrid form of a valid key' do
          key_pairs.each do |pair|
            raw = pair[:raw]
            hybrid = [0x06 | (raw.getbyte(64) & 1)].pack('C') + raw.byteslice(1..)
            assert_nil Triauth::Verifiers::Ecdsa.from_publishable_key(b64u.call(hybrid))
            assert_nil Triauth::Verifiers::WebAuthnEs256.from_publishable_key(b64u.call(hybrid))
          end
        end
      end

      # The describes below are port-only: they pin the crypto encodings of the profile's idiom table (no triauth-js
      # counterpart) against the fixtures and the recorded WebAuthn assertion.

      es256_import = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
      es256_verify = { name: 'ECDSA', hash: 'SHA-256' }
      ed25519_algorithm = { name: 'Ed25519' }

      # the john desktop key pair of fixtures/identities.json: the published 65-byte point and its JWK private key
      desktop = JSON.parse(File.read(File.join(__dir__, '..', 'fixtures', 'identities.json')))['john']['devices'][0]['keys'][0]

      # Builds the EC private key of a JWK (`d`, `x`, `y`) through the SEC1 `ECPrivateKey` DER (OpenSSL has no JWK import).
      ec_private_key_from_jwk = lambda do |jwk|
        d = Triauth::Helpers.base64url_to_uint8(jwk['d'])
        x = Triauth::Helpers.base64url_to_uint8(jwk['x'])
        y = Triauth::Helpers.base64url_to_uint8(jwk['y'])
        ec_private_key = [
          OpenSSL::ASN1::Integer(1),
          OpenSSL::ASN1::OctetString(d),
          OpenSSL::ASN1::ObjectId('prime256v1', 0, :EXPLICIT),
          OpenSSL::ASN1::BitString("\x04".b + x + y, 1, :EXPLICIT)
        ]
        OpenSSL::PKey::EC.new(OpenSSL::ASN1::Sequence(ec_private_key).to_der)
      end

      # OpenSSL signs to the DER `SEQUENCE { INTEGER r, INTEGER s }`; the wire carries the raw `r || s`.
      der_to_raw = lambda do |der|
        r, s = OpenSSL::ASN1.decode(der).value.map { |i| i.value.to_s(2) }
        r.rjust(32, "\x00") + s.rjust(32, "\x00")
      end

      describe 'Triauth.Verifiers.Base.import_key ES256 (port-only)' do
        it 'imports the 65-byte uncompressed point of the john desktop key as a prime256v1 public key' do
          raw = Triauth::Helpers.base64url_to_uint8(desktop['public'])
          assert_equal 65, raw.bytesize
          assert_equal 0x04, raw.getbyte(0)
          key = Triauth::Verifiers::Base.import_key(raw, es256_import)
          assert_kind_of OpenSSL::PKey::EC, key
          assert_equal 'prime256v1', key.group.curve_name
          assert_equal raw, key.public_key.to_octet_string(:uncompressed)
          refute key.private?
        end

        it 'raises for a compressed point, a 64-byte value, a 66-byte value, an off-curve point, an all-zero value and an unknown algorithm' do
          raw = Triauth::Helpers.base64url_to_uint8(desktop['public'])
          key = Triauth::Verifiers::Base.import_key(raw, es256_import)
          compressed = key.public_key.to_octet_string(:compressed)
          assert_equal 33, compressed.bytesize
          assert_raises(StandardError) { Triauth::Verifiers::Base.import_key(compressed, es256_import) }
          assert_raises(StandardError) { Triauth::Verifiers::Base.import_key(raw.byteslice(1, 64), es256_import) }
          assert_raises(StandardError) { Triauth::Verifiers::Base.import_key(raw + "\x00".b, es256_import) }
          off_curve = raw.dup
          off_curve.setbyte(64, off_curve.getbyte(64) ^ 1)
          assert_raises(StandardError) { Triauth::Verifiers::Base.import_key(off_curve, es256_import) }
          assert_raises(StandardError) { Triauth::Verifiers::Base.import_key("\x04".b + ("\x00".b * 64), es256_import) }
          assert_raises(StandardError) { Triauth::Verifiers::Base.import_key(raw, { name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' }) }
          assert_raises(StandardError) { Triauth::Verifiers::Base.import_key(raw, { name: 'RSA-PSS' }) }
        end
      end

      describe 'Triauth.Verifiers.Base.import_key Ed25519 (port-only)' do
        it 'imports the 32-byte key through the SPKI wrapper and raises for 31 and 33 bytes' do
          raw = Triauth::Helpers.base64url_to_uint8('Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0')
          assert_equal 32, raw.bytesize
          key = Triauth::Verifiers::Base.import_key(raw, ed25519_algorithm)
          assert_equal 'ED25519', key.oid
          assert_equal raw, key.public_to_der.byteslice(-32, 32)
          assert_raises(StandardError) { Triauth::Verifiers::Base.import_key(raw.byteslice(0, 31), ed25519_algorithm) }
          assert_raises(StandardError) { Triauth::Verifiers::Base.import_key(raw + "\x00".b, ed25519_algorithm) }
        end
      end

      describe 'Triauth.Verifiers.Base.raw_to_der (port-only)' do
        it 'writes minimal positive INTEGER encodings: a leading zero byte ahead of a high bit, leading zero bytes dropped' do
          r = "\xFF".b + ("\x01".b * 31)    # the high bit set: DER needs a leading zero byte
          s = ("\x00".b * 30) + "\x01\x02".b # leading zero bytes: DER drops them
          der = Triauth::Verifiers::Base.raw_to_der(r + s)
          assert_equal "\x30\x27\x02\x21\x00".b + r + "\x02\x02\x01\x02".b, der
          decoded = OpenSSL::ASN1.decode(der)
          assert_kind_of OpenSSL::ASN1::Sequence, decoded
          assert_equal [OpenSSL::BN.new(r, 2), OpenSSL::BN.new(s, 2)], decoded.value.map(&:value)
          # a zero half is the one-byte INTEGER 0
          assert_equal "\x02\x01\x00".b, Triauth::Verifiers::Base.raw_to_der("\x00".b * 64).byteslice(2, 3)
        end

        it 'refuses a 63-byte and a 65-byte signature: raw_to_der raises, verify_signature answers false without raising' do
          sig = OpenSSL::Random.random_bytes(64)
          assert_raises(StandardError) { Triauth::Verifiers::Base.raw_to_der(sig.byteslice(0, 63)) }
          assert_raises(StandardError) { Triauth::Verifiers::Base.raw_to_der(sig + "\x00".b) }
          key = Triauth::Verifiers::Base.import_key(Triauth::Helpers.base64url_to_uint8(desktop['public']), es256_import)
          assert_equal false, Triauth::Verifiers::Base.verify_signature(es256_verify, key, sig.byteslice(0, 63), 'data'.b)
          assert_equal false, Triauth::Verifiers::Base.verify_signature(es256_verify, key, sig + "\x00".b, 'data'.b)
          assert_equal false, Triauth::Verifiers::Base.verify_signature(es256_verify, key, sig, 'data'.b)
          assert_equal false, Triauth::Verifiers::Base.verify_signature(es256_verify, key, "\x00".b * 64, 'data'.b)
          assert_raises(StandardError) { Triauth::Verifiers::Base.verify_signature({ name: 'HMAC' }, key, sig, 'data'.b) }
          assert_raises(StandardError) { Triauth::Verifiers::Base.verify_signature({ name: 'ECDSA', hash: 'SHA-384' }, key, sig, 'data'.b) }
        end
      end

      describe 'Triauth.Verifiers.Ecdsa (port-only)' do
        it 'fromPublishableKey verifies a signature made with the fixture private key and answers false, never raises, for a tampered message or a malformed signature' do
          verifier = Triauth::Verifiers::Ecdsa.from_publishable_key(desktop['public'])
          assert_kind_of Triauth::Verifiers::Ecdsa, verifier
          assert_kind_of OpenSSL::PKey::EC, verifier.public_key
          assert_equal Triauth.config.keys, verifier.config.keys

          message = 'auth;john@triauthdemo.org;;https://example.com/;v1;1777454675000;;;hello'
          der_sig = ec_private_key_from_jwk.call(desktop['private']).sign('SHA256', message)
          raw_sig = der_to_raw.call(der_sig)
          assert_equal 64, raw_sig.bytesize
          signature = Triauth::Helpers.array_buffer_to_base64url(raw_sig)
          assert_equal true, verifier.verify(message, signature, {}, {})
          assert_equal false, verifier.verify("#{message}x", signature, {}, {})
          assert_equal false, verifier.verify(message, Triauth::Helpers.array_buffer_to_base64url(raw_sig.byteslice(0, 63)), {}, {})
          assert_equal false, verifier.verify(message, Triauth::Helpers.array_buffer_to_base64url(der_sig), {}, {}) # the DER form of the same signature is not 64 bytes
          assert_equal false, verifier.verify(message, Triauth::Helpers.array_buffer_to_base64url(OpenSSL::Random.random_bytes(64)), {}, {})
          assert_equal false, verifier.verify(message, 'not base64url!', {}, {})
          assert_equal false, verifier.verify(nil, signature, {}, {})
        end

        it 'fromPublishableKey returns nil, logging the cause at debug, for a non-base64url string and for a 64-byte key' do
          debug_lines = []
          logger = Object.new
          logger.define_singleton_method(:debug) { |*args| debug_lines.push(args) }
          assert_nil Triauth::Verifiers::Ecdsa.from_publishable_key('not base64url!', {}, {}, { logger: logger })
          raw = Triauth::Helpers.base64url_to_uint8(desktop['public'])
          assert_nil Triauth::Verifiers::Ecdsa.from_publishable_key(Triauth::Helpers.array_buffer_to_base64url(raw.byteslice(1, 64)), {}, {}, { logger: logger })
          assert_equal 2, debug_lines.length
          assert_kind_of TypeError, debug_lines[0][0]
          assert_kind_of TypeError, debug_lines[1][0] # since triauth-js 1.0.0-beta.3 the 64-byte key fails `Helpers.decode_p256_public_key` ahead of `import_key` (an `ArgumentError` from `import_key` until then)
        end
      end

      describe 'Triauth.Verifiers.Ed25519 (port-only)' do
        it 'fromPublishableKey verifies the verify.json Ed25519 envelope over its rebuilt payload and answers false for a non-string signature' do
          suite = JSON.parse(File.read(File.join(__dir__, '..', 'fixtures', 'json', 'verify.json')))
          t = suite['tests'].find { |x| x['name'] == 'Ed25519: valid Ed25519 signature from a type=ed25519 key verifies -> valid:true' }
          refute_nil t
          message, envelope = t['args']
          verifier = Triauth::Verifiers::Ed25519.from_publishable_key(t['expected']['keys'][0]['value'])
          assert_kind_of Triauth::Verifiers::Ed25519, verifier
          assert_equal 'ED25519', verifier.public_key.oid

          # the signed payload per signature.js: type;identifier;actor;via;v1;ts;signedMetadata;;message (the unsigned slot is empty)
          fields = envelope[1...-1].split(';', -1)
          assert_equal 9, fields.length
          type, identifier, actor, via, ver, ts, signed_md, _unsigned_md, signature = fields
          payload = [type, identifier, actor, via, ver, ts, signed_md, '', message].join(';')
          assert_equal 'sign;ed25519@triauthdemo.org;;https://example.com/;v1;1777454675000;;;Please verify this signed statement', payload
          assert_equal true, verifier.verify(payload, signature, {}, {})
          assert_equal false, verifier.verify("#{payload}x", signature, {}, {})
          assert_equal false, verifier.verify(payload, Triauth::Helpers.array_buffer_to_base64url(Triauth::Helpers.base64url_to_uint8(signature).byteslice(0, 63)), {}, {})
          assert_equal false, verifier.verify('some-message', nil, {}, {})
        end

        it 'fromPublishableKey returns nil for a 31-byte key and for a non-base64url string' do
          raw = Triauth::Helpers.base64url_to_uint8('Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0')
          assert_nil Triauth::Verifiers::Ed25519.from_publishable_key(Triauth::Helpers.array_buffer_to_base64url(raw.byteslice(0, 31)))
          assert_nil Triauth::Verifiers::Ed25519.from_publishable_key('not base64url!')
        end
      end

      describe 'Triauth.Verifiers.WebAuthnEs256 (port-only)' do
        # the recorded assertion of test_identity_keys.js (the test that carries a clientDataJSON)
        fixture = {
          publishableKey: 'BLz4Aq2-83mwY130EohDzyiC9kBabbb92CaiRHVoEJGrV-vT2N1F-yRqSReT_ixAzti8ZBX6q5ISEHBStcISrAM',
          challenge: 'eyJjYnVybCI6Ii0iLCJzdWIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoiY0dOcE0xLTQyRWY3MVNXbWozX1NCekpUIiwiaWF0IjoxNzcyNzk4ODg1MDUyLCJ2ZXIiOjF9',
          clientDataJSON: '{"type":"webauthn.get","challenge":"K5Y3CSaQpudj72n_Uz-ZxvyVBVygyh0yEp4fguKmhjY","origin":"http://localhost:8080","crossOrigin":false}',
          authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAw',
          signature: '0UKhAqv1LVGwJU6slDq-vungPeOQlj1sdHkF0Yh7w33r8X6SqjKS_kq-CcSqGWPRZWkgK_vobcHSlkWC0PPO-Q'
        }
        context = { idx: 0, mode: 'auth' }
        # `sig` is keyed by the index string of the JS object: the Symbol `:"0"` here
        unsigned_data = { sig: { '0': { clientDataJSON: fixture[:clientDataJSON], authenticatorData: fixture[:authenticatorData] } } }
        # the same assertion with another clientDataJSON text or authenticatorData
        with = lambda do |client_data_json: fixture[:clientDataJSON], authenticator_data: fixture[:authenticatorData]|
          { sig: { '0': { clientDataJSON: client_data_json, authenticatorData: authenticator_data } } }
        end

        it 'verifies the recorded assertion, with a matching webAuthnOrigin, with an empty one and without one' do
          verifier = Triauth::Verifiers::WebAuthnEs256.from_publishable_key(fixture[:publishableKey], {}, context)
          assert_kind_of Triauth::Verifiers::WebAuthnEs256, verifier
          assert_kind_of OpenSSL::PKey::EC, verifier.public_key
          assert_equal context, verifier.context
          assert_equal({}, verifier.options)
          assert_equal Triauth.config.keys, verifier.config.keys
          assert_equal true, verifier.verify(fixture[:challenge], fixture[:signature], {}, unsigned_data)
          same_origin = Triauth::Verifiers::WebAuthnEs256.from_publishable_key(fixture[:publishableKey], {}, context.merge(webAuthnOrigin: 'http://localhost:8080'))
          assert_equal true, same_origin.verify(fixture[:challenge], fixture[:signature], {}, unsigned_data)
          # an empty webAuthnOrigin is "not available from context" (the JS `expectedOrigin &&` on a string)
          empty_origin = Triauth::Verifiers::WebAuthnEs256.from_publishable_key(fixture[:publishableKey], {}, context.merge(webAuthnOrigin: ''))
          assert_equal true, empty_origin.verify(fixture[:challenge], fixture[:signature], {}, unsigned_data)
        end

        it 'answers false for a changed challenge, crossOrigin null or true, a second "challenge": key, a different webAuthnOrigin, every malformed unsignedData shape and a bad signature' do
          verifier = Triauth::Verifiers::WebAuthnEs256.from_publishable_key(fixture[:publishableKey], {}, context)
          # the message changed: clientData.challenge is no longer sha256(message)
          assert_equal false, verifier.verify("#{fixture[:challenge]}x", fixture[:signature], {}, unsigned_data)
          # crossOrigin present as an explicit null (present and not exactly false, rejected as in triauth-js), and as true
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, with.call(client_data_json: fixture[:clientDataJSON].sub('"crossOrigin":false', '"crossOrigin":null')))
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, with.call(client_data_json: fixture[:clientDataJSON].sub('"crossOrigin":false', '"crossOrigin":true')))
          # a second "challenge": key in the JSON text (nested, so that the top-level challenge still matches)
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, with.call(client_data_json: fixture[:clientDataJSON].sub('"crossOrigin":false', '"crossOrigin":false,"x":{"challenge":1}')))
          # a type other than webauthn.get, and a clientDataJSON that is not a JSON object
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, with.call(client_data_json: fixture[:clientDataJSON].sub('"webauthn.get"', '"webauthn.create"')))
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, with.call(client_data_json: '[]'))
          # an expected origin from the context that differs
          other_origin = Triauth::Verifiers::WebAuthnEs256.from_publishable_key(fixture[:publishableKey], {}, context.merge(webAuthnOrigin: 'https://other.example'))
          assert_equal false, other_origin.verify(fixture[:challenge], fixture[:signature], {}, unsigned_data)
          # unsignedData shapes: nil, a String, no sig, an Array sig, the wrong index, a String entry, a non-string clientDataJSON, a non-base64url authenticatorData
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, nil)
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, 'unsigned')
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, {})
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, { sig: [] })
          # ... while an Array sig is read by position, as the JS `sig[idx]` does: the recorded assertion verifies through it, and a negative or out-of-range idx reads nothing
          array_sig = { sig: [{ clientDataJSON: fixture[:clientDataJSON], authenticatorData: fixture[:authenticatorData] }] }
          assert_equal true, verifier.verify(fixture[:challenge], fixture[:signature], {}, array_sig)
          assert_equal false, Triauth::Verifiers::WebAuthnEs256.from_publishable_key(fixture[:publishableKey], {}, { idx: -1, mode: 'auth' }).verify(fixture[:challenge], fixture[:signature], {}, array_sig)
          assert_equal false, Triauth::Verifiers::WebAuthnEs256.from_publishable_key(fixture[:publishableKey], {}, { idx: 1, mode: 'auth' }).verify(fixture[:challenge], fixture[:signature], {}, array_sig)
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, { sig: { '1': unsigned_data[:sig][:'0'] } })
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, { sig: { '0': fixture[:clientDataJSON] } })
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, with.call(client_data_json: 123))
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, with.call(authenticator_data: 'not base64url!'))
          # the signature itself: tampered, 63 bytes, and not base64url
          assert_equal false, verifier.verify(fixture[:challenge], "#{fixture[:signature][0...-1]}A", {}, unsigned_data)
          assert_equal false, verifier.verify(fixture[:challenge], Triauth::Helpers.array_buffer_to_base64url(Triauth::Helpers.base64url_to_uint8(fixture[:signature]).byteslice(0, 63)), {}, unsigned_data)
          assert_equal false, verifier.verify(fixture[:challenge], 'not base64url!', {}, unsigned_data)
        end

        it 'rejects truncated authenticatorData, a cleared User Present flag and, under uv=required, a cleared User Verified flag, each with its debug line' do
          debug_lines = []
          logger = Object.new
          logger.define_singleton_method(:debug) { |*args| debug_lines.push(args) }
          authenticator_data_bytes = Triauth::Helpers.base64url_to_uint8(fixture[:authenticatorData])
          assert_equal 37, authenticator_data_bytes.bytesize
          assert_equal 0x01, authenticator_data_bytes.getbyte(32) # UP set, UV clear
          verifier = Triauth::Verifiers::WebAuthnEs256.from_publishable_key(fixture[:publishableKey], {}, context, { logger: logger })
          # 36 bytes: shorter than rpIdHash + flags + signCount
          truncated = Triauth::Helpers.array_buffer_to_base64url(authenticator_data_bytes.byteslice(0, 36))
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, with.call(authenticator_data: truncated))
          assert_equal [['WebAuthn assertion rejected - authenticatorData shorter than 37 bytes']], debug_lines
          debug_lines.clear
          # UP cleared
          silent = authenticator_data_bytes.dup
          silent.setbyte(32, 0x00)
          assert_equal false, verifier.verify(fixture[:challenge], fixture[:signature], {}, with.call(authenticator_data: Triauth::Helpers.array_buffer_to_base64url(silent)))
          assert_equal [['WebAuthn assertion rejected - User Present (UP) flag not set']], debug_lines
          debug_lines.clear
          # uv=required against the recorded assertion (UV clear) fails; any other uv value never reaches the verifier
          uv_required = Triauth::Verifiers::WebAuthnEs256.from_publishable_key(fixture[:publishableKey], { uv: 'required' }, context, { logger: logger })
          assert_equal({ uv: 'required' }, uv_required.options)
          assert_equal false, uv_required.verify(fixture[:challenge], fixture[:signature], {}, unsigned_data)
          assert_equal [['WebAuthn assertion rejected - User Verified (UV) flag required by key options but not set']], debug_lines
          debug_lines.clear
          # without uv=required the same assertion verifies, and nothing is logged
          assert_equal true, verifier.verify(fixture[:challenge], fixture[:signature], {}, unsigned_data)
          assert_empty debug_lines
          # a rescued error is logged as the error object
          assert_equal false, verifier.verify(nil, fixture[:signature], {}, unsigned_data)
          assert_equal 1, debug_lines.length
          assert_kind_of TypeError, debug_lines[0][0]
        end

        it 'the algorithm-agnostic WebAuthn base answers nil from fromPublishableKey and false from verify, each with its debug line' do
          debug_lines = []
          logger = Object.new
          logger.define_singleton_method(:debug) { |*args| debug_lines.push(args) }
          assert_nil Triauth::Verifiers::WebAuthn.import_algorithm
          assert_nil Triauth::Verifiers::WebAuthn.verify_algorithm
          assert_nil Triauth::Verifiers::WebAuthn.from_publishable_key(fixture[:publishableKey], {}, context, { logger: logger })
          key = Triauth::Verifiers::Base.import_key(Triauth::Helpers.base64url_to_uint8(fixture[:publishableKey]), es256_import)
          assert_equal false, Triauth::Verifiers::WebAuthn.new(key, {}, context, { logger: logger }).verify(fixture[:challenge], fixture[:signature], {}, unsigned_data)
          assert_equal [['WebAuthn is an algorithm-agnostic base verifier - use a concrete subclass (e.g., WebAuthnEs256)']] * 2, debug_lines
          # the concrete subclasses bind the WebCrypto identifiers as data
          assert_equal es256_import, Triauth::Verifiers::WebAuthnEs256.import_algorithm
          assert_equal es256_verify, Triauth::Verifiers::WebAuthnEs256.verify_algorithm
          assert_equal ed25519_algorithm, Triauth::Verifiers::WebAuthnEd25519.import_algorithm
          assert_equal ed25519_algorithm, Triauth::Verifiers::WebAuthnEd25519.verify_algorithm
        end
      end

      describe 'Triauth.Verifiers.WebAuthnEd25519 (port-only)' do
        it 'verifies a synthetic Ed25519 assertion over authenticatorData || sha256(clientDataJSON) and honors uv=required' do
          private_key = OpenSSL::PKey.generate_key('ED25519')
          publishable_key = Triauth::Helpers.array_buffer_to_base64url(private_key.public_to_der.byteslice(-32, 32)) # the raw key: the SPKI DER minus its 12-byte prefix
          message = 'eyJ0ZXN0IjoxfQ'
          client_data_json = JSON.generate({ type: 'webauthn.get', challenge: Triauth::Helpers.sha256(message), origin: 'https://auth.example.com', crossOrigin: false })
          # rpIdHash (32 bytes) || flags || signCount (4 bytes), with UP and UV set
          authenticator_data = OpenSSL::Digest.digest('SHA256', 'auth.example.com') + "\x05".b + ("\x00".b * 4)
          sign = lambda do |auth_data|
            Triauth::Helpers.array_buffer_to_base64url(private_key.sign(nil, auth_data + OpenSSL::Digest::SHA256.digest(client_data_json)))
          end
          unsigned = lambda do |auth_data|
            { sig: { '0': { clientDataJSON: client_data_json, authenticatorData: Triauth::Helpers.array_buffer_to_base64url(auth_data) } } }
          end
          verifier = Triauth::Verifiers::WebAuthnEd25519.from_publishable_key(publishable_key, { uv: 'required' }, { idx: 0, mode: 'auth', webAuthnOrigin: 'https://auth.example.com' })
          assert_kind_of Triauth::Verifiers::WebAuthnEd25519, verifier
          assert_equal 'ED25519', verifier.public_key.oid
          assert_equal true, verifier.verify(message, sign.call(authenticator_data), {}, unsigned.call(authenticator_data))
          assert_equal false, verifier.verify("#{message}x", sign.call(authenticator_data), {}, unsigned.call(authenticator_data))
          # UV cleared under uv=required
          up_only = authenticator_data.dup
          up_only.setbyte(32, 0x01)
          assert_equal false, verifier.verify(message, sign.call(up_only), {}, unsigned.call(up_only))
          # the same assertion under a key record without uv=required verifies
          relaxed = Triauth::Verifiers::WebAuthnEd25519.from_publishable_key(publishable_key, {}, { idx: 0, mode: 'auth' })
          assert_equal true, relaxed.verify(message, sign.call(up_only), {}, unsigned.call(up_only))
          # the ES256 verifiers never accept an Ed25519 key, nor the Ed25519 ones a P-256 point
          assert_nil Triauth::Verifiers::WebAuthnEs256.from_publishable_key(publishable_key)
          assert_nil Triauth::Verifiers::WebAuthnEd25519.from_publishable_key(desktop['public'])
        end
      end

      describe 'Triauth.Verifiers registry (port-only)' do
        it 'lists the four built-in types in registration order and answers nil for an unknown type' do
          assert_equal %w[es256 ed25519 webauthn-es256 webauthn-ed25519], Triauth::Verifiers.list
          assert_equal Triauth::Verifiers::Ecdsa, Triauth::Verifiers.get('es256')
          assert_equal Triauth::Verifiers::Ed25519, Triauth::Verifiers.get('ed25519')
          assert_equal Triauth::Verifiers::WebAuthnEs256, Triauth::Verifiers.get('webauthn-es256')
          assert_equal Triauth::Verifiers::WebAuthnEd25519, Triauth::Verifiers.get('webauthn-ed25519')
          assert_nil Triauth::Verifiers.get('bogus')
          assert_nil Triauth::Verifiers.get(:es256) # the registry keys are wire values: Strings, never Symbols
          assert_nil Triauth::Verifiers.get(nil)
        end

        it 'lists an integer-like type first in numeric order, as Object.keys does, and the rest in registration order' do
          registry = Triauth::Verifiers.instance_variable_get(:@verifiers) # there is no unregister API: the test removes its own entries
          begin
            Triauth::Verifiers.register('123', Triauth::Verifiers::Ecdsa)
            Triauth::Verifiers.register('7', Triauth::Verifiers::Ed25519)
            assert_equal %w[7 123 es256 ed25519 webauthn-es256 webauthn-ed25519], Triauth::Verifiers.list
            assert_equal Triauth::Verifiers::Ecdsa, Triauth::Verifiers.get('123')
            assert_equal Triauth::Verifiers::Ed25519, Triauth::Verifiers.get('7')
          ensure
            registry.delete('123')
            registry.delete('7')
          end
          assert_equal %w[es256 ed25519 webauthn-es256 webauthn-ed25519], Triauth::Verifiers.list
        end
      end
    end
  end
end

TestInternals.verifiers if __FILE__ == $PROGRAM_NAME
