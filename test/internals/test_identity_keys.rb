# frozen_string_literal: true

require_relative '../setup'
require_relative '../stubs/signer'
require 'json'
require 'openssl'

module TestInternals
  def self.identity_keys
    identities = JSON.parse(File.read(File.expand_path('../fixtures/identities.json', __dir__)), symbolize_names: true)

    describe 'Triauth.IdentityKeys' do
      describe 'Triauth.IdentityKeys.add' do
        key_val = 'BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8'

        it 'accepts valid keys' do
          ik = Triauth::IdentityKeys.new

          assert_equal true, ik.add("desktop[1/1]:#{key_val}")

          assert_equal true, ik.add("laptop[1/2]:#{key_val}")
          assert_equal true, ik.add("laptop[2/2]:#{key_val}")

          assert_equal 2, ik.count
          ik.key_groups.each_value do |key_group|
            assert_equal true, key_group[:valid]
            refute key_group[:tainted]
            assert_kind_of String, key_group[:tag]
          end
        end

        it 'does not mutate the caller-supplied options object (works on a private copy)' do
          ik = Triauth::IdentityKeys.new
          options = {} # no type/use given - add() fills the defaults internally

          assert_equal true, ik.add("desktop[1/1]:#{key_val}", options)

          # The caller's object must be left untouched (defaults are applied to a private copy)...
          assert_equal({}, options)

          # ...while the stored keyGroup key carries the defaulted copy, which is NOT the same reference.
          assert_equal({ type: 'es256', use: 'attest,auth,ping,sign,stamp' }, ik.key_groups[:desktop][:keys][0][:options])
          refute_same options, ik.key_groups[:desktop][:keys][0][:options]
        end

        it 'does not accept keys with unknown syntax' do
          ik = Triauth::IdentityKeys.new

          assert_equal false, ik.add("lap_top[1/1]:#{key_val}")

          assert_equal 0, ik.key_groups.size
        end

        it 'rejects device names longer than the record-name regex / device-name limit allows ({1,20})' do
          ik = Triauth::IdentityKeys.new

          # 21-char name exceeds the add() regex ({1,20}) — and the 20-byte device-name limit — so it is rejected outright
          assert_equal false, ik.add("aaaaaaaaaaaaaaaaaaaaa[1/1]:#{key_val}")
          assert_equal 0, ik.key_groups.size
        end

        it 'does not accept keys with obviously invalid position and/or count and taints the whole keyGroup' do
          ik = Triauth::IdentityKeys.new

          assert_equal false, ik.add("laptop1[1/0]:#{key_val}")
          assert_equal false, ik.add("laptop2[0/2]:#{key_val}")
          assert_equal false, ik.add("laptop3[2/02]:#{key_val}")
          assert_equal false, ik.add("laptop4[2/1]:#{key_val}")

          assert_equal 4, ik.key_groups.size
          assert_equal 0, ik.count, 'no valid keyGroups should be present'
          ik.key_groups.each_value do |key|
            refute key[:valid]
            assert_equal true, key[:tainted]
          end
        end

        it 'observes the maxKeysPerDevice limit' do
          ik = Triauth::IdentityKeys.new
          max_keys_per_device = Triauth::LIMITS[:maxKeysPerDevice]

          assert_equal true, ik.add("desktop[#{max_keys_per_device}/#{max_keys_per_device}]:#{key_val}")
          assert_equal false, ik.add("laptop[#{max_keys_per_device + 1}/#{max_keys_per_device + 1}]:#{key_val}")
        end

        it 'observes the maxDevices limit' do
          ik = Triauth::IdentityKeys.new
          max_devices = Triauth::LIMITS[:maxDevices]

          max_devices.times do |i|
            assert_equal true, ik.add("device#{i}[1/1]:#{key_val}")
          end

          assert_equal false, ik.add("device[1/1]:#{key_val}")
        end

        it 'does not accept keys when keyCount is not consistent and taints the whole keyGroup' do
          ik = Triauth::IdentityKeys.new
          keys_count = 3

          (1..(keys_count - 1)).each do |i|
            assert_equal true, ik.add("device[#{i}/#{keys_count}]:#{key_val}")
          end

          assert_equal false, ik.add("device[#{keys_count}/#{keys_count - 1}]:#{key_val}"), 'key with incosistent keyCount should not be accepted'

          refute ik.key_groups[:device][:valid], 'keyGroup should not be valid'
          assert_equal true, ik.key_groups[:device][:tainted], 'keyGroup should be tainted'

          assert_equal false, ik.add("device[#{keys_count}/#{keys_count}]:#{key_val}"), 'should not be possible to add keys to a tainted group'
          refute ik.key_groups[:device][:valid], 'keyGroup should remain not valid'
        end

        it 'does not accept keys at duplicated positions and taints the whole keyGroup' do
          ik = Triauth::IdentityKeys.new
          keys_count = 2

          (1..keys_count).each do |i|
            assert_equal true, ik.add("device[#{i}/#{keys_count}]:#{key_val}")
          end

          assert ik.key_groups[:device][:valid], 'keyGroup should be valid at this point, before a conflicting key is added'
          assert_equal 1, ik.count

          assert_equal false, ik.add("device[1/#{keys_count}]:#{key_val}"), 'key at colliding index should not be accepted'

          refute ik.key_groups[:device][:valid], 'keyGroup should be invalidated upon collision'
          assert_equal true, ik.key_groups[:device][:tainted]
          assert_equal 0, ik.count
        end

        it 'does not mark sparse keyGroups valid before every declared key slot is populated' do
          ik = Triauth::IdentityKeys.new
          keys_count = 3

          assert_equal true, ik.add("device[3/#{keys_count}]:#{key_val}")
          assert_equal keys_count, ik.key_groups[:device][:keys].length # the Array grown with nil slots has the JS sparse length
          assert_equal 1, ik.key_groups[:device][:keys].compact.length # `Object.keys(sparseArray).length`: the populated slots
          refute ik.key_groups[:device][:valid]
          assert_equal 0, ik.count

          assert_equal true, ik.add("device[1/#{keys_count}]:#{key_val}")
          assert_equal 2, ik.key_groups[:device][:keys].compact.length
          refute ik.key_groups[:device][:valid]
          assert_equal 0, ik.count

          assert_equal true, ik.add("device[2/#{keys_count}]:#{key_val}")
          assert_equal keys_count, ik.key_groups[:device][:keys].compact.length
          assert_equal true, ik.key_groups[:device][:valid]
          assert_equal 1, ik.count
        end

        it 'correctly maintains the expires status' do
          ik = Triauth::IdentityKeys.new
          # (the unused `keyCount` constant of the JS test is not declared: an unused local is a lint defect here)

          assert_equal true, ik.add("device[1/3]:#{key_val}", {}, { expires: 10 })
          assert_equal true, ik.add("device[2/3]:#{key_val}", {}, { expires: 5 })
          assert_equal true, ik.add("device[3/3]:#{key_val}", {}, { expires: 12 })

          assert ik.key_groups[:device][:valid]
          assert_equal 5, ik.key_groups[:device][:expires]
        end

        it 'keyGroup.expires stays undefined when no key in the group has a TTL (keyMetadata.expires is undefined)' do
          # Exercises the identity.js path where `typeof entry.ttl !== 'number'` → expires=undefined,
          # and the identity_keys.js path where `if (keyMetadata.expires && ...)` is false → keyGroup.expires stays undefined.
          # JSON.stringify drops undefined, so this branch cannot be covered by the JSON test framework.
          ik = Triauth::IdentityKeys.new

          assert_equal true, ik.add("device[1/2]:#{key_val}", {}, { secure: true })
          assert_equal true, ik.add("device[2/2]:#{key_val}", {}, { secure: true })

          assert ik.key_groups[:device][:valid]
          assert_nil ik.key_groups[:device][:expires]
          assert ik.key_groups[:device].key?(:expires)
        end

        it 'does not accept non base64-url key values and taints the whole keyGroup' do
          ik = Triauth::IdentityKeys.new

          assert_equal true, ik.add("device[1/2]:#{key_val}")

          assert_equal false, ik.add("device[2/2]:@#{key_val}")
          assert_equal true, ik.key_groups[:device][:tainted]
          assert_equal 0, ik.count
        end

        it 'does not accept unknown values for known key options and taints the whole group' do
          ik = Triauth::IdentityKeys.new

          assert_equal true, ik.add("device[1/2]:#{key_val}", { type: 'es256' })
          assert_equal false, ik.add("device[2/2]:#{key_val}", { type: '-----' })

          refute ik.key_groups[:device][:valid]
          assert_equal true, ik.key_groups[:device][:tainted]
          assert_equal 0, ik.count
        end

        it 'judges a prototype-poisoning option name like any other unknown critical option and taints the whole group' do
          %w[__proto__ constructor prototype toString].each do |name|
            ik = Triauth::IdentityKeys.new
            options = { name.to_sym => 'evil' } # `Object.create(null)` with the one member: a plain Hash keyed by the option name

            assert_equal false, ik.add("device[1/1]:#{key_val}", options), name
            assert_equal true, ik.key_groups[:device][:tainted], name
            assert_equal 0, ik.count, name
          end
        end

        it 'skips over unknown x- experimental options for future compatibility' do
          ik = Triauth::IdentityKeys.new

          assert_equal true, ik.add("device[1/2]:#{key_val}", { type: 'es256' })
          assert_equal true, ik.add("device[2/2]:#{key_val}", { 'x-futureoption': '-----' })

          assert ik.key_groups[:device][:valid]
          refute ik.key_groups[:device][:tainted]
          assert_equal 1, ik.count
        end
      end

      describe 'Triauth.IdentityKeys.verify' do
        # a method, not a lambda: a lambda in a describe body cannot assert (its `self` is the spec class);
        # the parameter is `identities` in JS, renamed here so that it does not shadow the fixture local of the suite
        define_method(:for_each_device) do |identities_arg, &callback|
          identities_arg.each_value do |identity|
            identity[:devices].each do |device|
              identity_keys = Triauth::IdentityKeys.new
              message = 'Lorem ipsum dolor'

              signatures = []
              device[:keys].each do |key_pair|
                signer_stub = SignerStub.from_jwk(key_pair[:private])
                signature = signer_stub.sign(message)
                signatures.push(signature[0])

                key_idx = signatures.length
                key_count = device[:keys].length

                assert_equal true, identity_keys.add("#{device[:deviceName]}[#{key_idx}/#{key_count}]:#{key_pair[:public]}")
              end

              callback.call({ identity: identity, device: device, identityKeys: identity_keys, message: message, signatures: signatures })
            end
          end
        end

        it 'verifies valid signatures' do
          for_each_device(identities) do |opts|
            device, identity_keys, message, signatures = opts.values_at(:device, :identityKeys, :message, :signatures)
            assert_equal true, identity_keys.key_groups[device[:deviceName].to_sym][:valid]

            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })

            assert_equal device[:deviceName], verify_result[:name]
            assert_equal device[:deviceTag], verify_result[:tag]
          end
        end

        it 'observes the maxKeysPerSignature limit' do
          max_signatures = Triauth::LIMITS[:maxKeysPerSignature]

          for_each_device(identities) do |opts|
            device, identity_keys, message, signatures = opts.values_at(:device, :identityKeys, :message, :signatures)
            assert_equal true, identity_keys.key_groups[device[:deviceName].to_sym][:valid]

            limit_left = max_signatures - signatures.length

            limit_left.times do
              signatures.push(signatures[0])
              verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })

              assert_equal device[:deviceName], verify_result[:name]
              assert_equal device[:deviceTag], verify_result[:tag]
            end

            signatures.push(signatures[0])
            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })

            refute verify_result
          end
        end

        it 'expects strictly only base64Url encoded signatures' do
          for_each_device(identities) do |opts|
            _device, identity_keys, message, signatures = opts.values_at(:device, :identityKeys, :message, :signatures)
            signatures.push('@')

            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })

            refute verify_result
          end
        end

        it 'does not verify mangled keys' do
          for_each_device(identities) do |opts|
            device, identity_keys, message, signatures = opts.values_at(:device, :identityKeys, :message, :signatures)
            identity_keys.key_groups[device[:deviceName].to_sym][:keys][0][:value] += 'a'

            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })

            refute verify_result
          end
        end

        it 'does not verify mangled signatures' do
          for_each_device(identities) do |opts|
            _device, identity_keys, message, signatures = opts.values_at(:device, :identityKeys, :message, :signatures)
            signatures[0] += 'a'

            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })

            refute verify_result
          end
        end

        it 'does not take into account non-valid keyGroups' do
          for_each_device(identities) do |opts|
            device, identity_keys, message, signatures = opts.values_at(:device, :identityKeys, :message, :signatures)

            identity_keys.key_groups[device[:deviceName].to_sym][:valid] = false
            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })
            refute verify_result

            identity_keys.key_groups[device[:deviceName].to_sym][:valid] = nil
            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })
            refute verify_result
          end
        end

        it 'propagates expires:undefined to the verify result when no key has a TTL' do
          # Exercises the `expires: keyGroup.expires` return at identity_keys.js:300
          # when keyGroup.expires was never set (all keys added without a TTL).
          # JSON.stringify drops `undefined` values, so this branch cannot be reached via the JSON test framework.
          ik = Triauth::IdentityKeys.new
          message = 'Lorem ipsum dolor'

          identity = identities.values[0]
          device = identity[:devices][0]
          signatures = []

          device[:keys].each_with_index do |key_pair, idx|
            key_idx = idx + 1
            key_count = device[:keys].length
            signer_stub = SignerStub.from_jwk(key_pair[:private])
            signature = signer_stub.sign(message)
            signatures.push(signature[0])
            # Pass keyMetadata without 'expires' — simulates a DNS record without a TTL
            assert_equal true, ik.add("#{device[:deviceName]}[#{key_idx}/#{key_count}]:#{key_pair[:public]}", {}, { secure: true })
          end

          assert_nil ik.key_groups[device[:deviceName].to_sym][:expires]

          verify_result = ik.verify(message, signatures, { mode: 'auth' })
          assert verify_result, 'verify must succeed'
          assert verify_result.key?(:expires), 'expires must be an own property of the result'
          assert_nil verify_result[:expires], 'expires must be undefined when no key had a TTL'
        end

        # @todo - check
        it 'verifies keyGroups within the clock-drift grace window after their expires has passed' do
          # The in-call expiry check allows a grace window equal to `maximalAllowedClientClockDrift` after
          # `expires` so that DNS records published with TTL=0 (whose `expires` equals the resolution
          # moment) still verify within the same call. KeyGroups older than that grace are skipped —
          # protecting against external misuse where an Identity is held across calls.
          # The DNS-published expiry value itself is propagated to the caller unchanged.
          for_each_device(identities) do |opts|
            device, identity_keys, message, signatures = opts.values_at(:device, :identityKeys, :message, :signatures)
            drift = Triauth.config[:maximalAllowedClientClockDrift]

            # TTL=0 case — expires equals "now" at resolution; well within the drift grace.
            identity_keys.key_groups[device[:deviceName].to_sym][:expires] = Triauth::Helpers.date_now
            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })
            assert verify_result, 'TTL=0 records (expires == Date.now()) must verify within the drift grace'
            assert_equal device[:deviceName], verify_result[:name]

            # expires slightly in the past, but still within the drift grace — verifies; original value propagated.
            expires_in_past = Triauth::Helpers.date_now - 1
            identity_keys.key_groups[device[:deviceName].to_sym][:expires] = expires_in_past
            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })
            assert verify_result, 'expires within the drift grace must NOT block in-call verification'
            assert_equal expires_in_past, verify_result[:expires], 'the original expires value is propagated to the result'

            # expires older than the drift grace — keyGroup is skipped.
            identity_keys.key_groups[device[:deviceName].to_sym][:expires] = Triauth::Helpers.date_now - drift - 1000
            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })
            refute verify_result, 'expires older than maximalAllowedClientClockDrift must skip the keyGroup'
          end
        end

        it 'does not verify keys of unrecognized type' do
          for_each_device(identities) do |opts|
            device, identity_keys, message, signatures = opts.values_at(:device, :identityKeys, :message, :signatures)

            identity_keys.key_groups[device[:deviceName].to_sym][:keys][0][:options][:type] = 'unrecognized-type'

            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })
            refute verify_result
          end
        end

        it 'correctly verifies the use option' do
          for_each_device(identities) do |opts|
            device, identity_keys, message, signatures = opts.values_at(:device, :identityKeys, :message, :signatures)
            keys_count = identity_keys.key_groups[device[:deviceName].to_sym][:keys].length

            identity_keys.key_groups[device[:deviceName].to_sym][:keys][0][:options][:use] = 'auth'

            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })
            assert verify_result

            verify_result = identity_keys.verify(message, signatures, { mode: 'sign' })
            assert(keys_count > 1 ? verify_result : !verify_result)

            verify_result = identity_keys.verify(message, signatures, { mode: 'stamp' })
            assert(keys_count > 1 ? verify_result : !verify_result)

            verify_result = identity_keys.verify(message, signatures, { mode: 'missing' })
            refute verify_result

            identity_keys.key_groups[device[:deviceName].to_sym][:keys][0][:options][:use] = 'auth,sign'

            verify_result = identity_keys.verify(message, signatures, { mode: 'auth' })
            assert verify_result

            verify_result = identity_keys.verify(message, signatures, { mode: 'sign' })
            assert verify_result

            verify_result = identity_keys.verify(message, signatures, { mode: 'stamp' })
            assert(keys_count > 1 ? verify_result : !verify_result)

            verify_result = identity_keys.verify(message, signatures, { mode: 'missing' })
            refute verify_result
          end
        end

        it 'validates webauthn signatures' do
          # Real browser-recorded assertion. The payload is opaque bytes at this layer (WebAuthn
          # checks clientData.challenge === sha256(payload), never parses it), so the recorded
          # challenge blob must stay byte-exact regardless of the current challenge JSON shape.
          # @todo: Update the challenge here to match the currently used structure
          fixture = {
            identifier: 'john@triauthdemo.org',
            callbackUrl: '-',
            publishableKey: 'BLz4Aq2-83mwY130EohDzyiC9kBabbb92CaiRHVoEJGrV-vT2N1F-yRqSReT_ixAzti8ZBX6q5ISEHBStcISrAM',
            challenge: 'eyJjYnVybCI6Ii0iLCJzdWIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyIsIm5vbmNlIjoiY0dOcE0xLTQyRWY3MVNXbWozX1NCekpUIiwiaWF0IjoxNzcyNzk4ODg1MDUyLCJ2ZXIiOjF9',
            clientDataJSON: '{"type":"webauthn.get","challenge":"K5Y3CSaQpudj72n_Uz-ZxvyVBVygyh0yEp4fguKmhjY","origin":"http://localhost:8080","crossOrigin":false}',
            authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAw',
            signature: '0UKhAqv1LVGwJU6slDq-vungPeOQlj1sdHkF0Yh7w33r8X6SqjKS_kq-CcSqGWPRZWkgK_vobcHSlkWC0PPO-Q'
          }

          _identifier, _callback_url, publishable_key, challenge, client_data_json, authenticator_data, signature =
            fixture.values_at(:identifier, :callbackUrl, :publishableKey, :challenge, :clientDataJSON, :authenticatorData, :signature)

          unsigned_data = { sig: { '0': { clientDataJSON: client_data_json, authenticatorData: authenticator_data } } }

          # triauth-js constructs `new Triauth.IdentityKeys('john@triauthdemo.org')` (an identifier in the config position, harmless there)
          ik = Triauth::IdentityKeys.new
          key_add_result = ik.add("device[1/1]:#{publishable_key}", { type: 'webauthn-es256' })

          assert_equal true, key_add_result
          assert ik.key_groups[:device][:valid]
          assert_equal 1, ik.count

          verify_result = ik.verify(challenge, [signature], { mode: 'auth' }, {}, unsigned_data)

          assert verify_result
          assert_equal 'device', verify_result[:name]
          assert_equal true, verify_result[:keys][0][:verified]
          assert_equal false, verify_result[:keys][0][:skipped]

          # the two negative calls pass the string 'auth' as the context in triauth-js (no `mode` to read there); `{ mode: 'auth' }` here
          verify_result = ik.verify("#{challenge}z", [signature], { mode: 'auth' }, {}, unsigned_data)
          assert_equal false, verify_result, 'should not verify non-matching challanges'

          verify_result = ik.verify(challenge, ["#{signature}a"], { mode: 'auth' }, {}, unsigned_data)
          assert_equal false, verify_result, 'should not verify non-matching signatures'
        end

        it 'rejects webauthn assertions without the User Present (UP) flag or with truncated authenticatorData' do
          john_key = identities[:john][:devices][0][:keys][0]
          message = 'up-flag-test-message'

          # Mint a fresh, correctly signed assertion with the given flags byte (and optional truncation),
          # so that a rejection can only come from the flags/length checks - not from the crypto verification.
          mk_assertion = lambda do |flags_byte, length = 37|
            auth_data = ("\xAA".b * 32) + [flags_byte].pack('C') + ("\x00".b * 4) # arbitrary rpIdHash (not checked - the key is pinned in DNS); bytes 33-36 (signCount) left as 0
            trimmed = auth_data.byteslice(0, length)

            client_data_json = JSON.generate({ type: 'webauthn.get', challenge: Triauth::Helpers.sha256(message), origin: 'https://triauthdemo.org', crossOrigin: false })

            cdj_hash = OpenSSL::Digest::SHA256.digest(Triauth::Helpers.string_to_utf8_bytes(client_data_json))
            payload = trimmed + cdj_hash
            # `crypto.subtle.importKey('jwk', ...)` and `crypto.subtle.sign`: the OpenSSL key of the JWK signs to DER, converted to the raw `r || s`
            private_key = SignerStub.from_jwk(john_key[:private]).private_keys[0]
            signature = Triauth::Helpers.array_buffer_to_base64url(OpenSSL::ASN1.decode(private_key.sign('SHA256', payload)).value.map { |i| i.value.to_s(2).rjust(32, "\x00".b) }.join)

            { signature: signature, unsignedData: { sig: { '0': { clientDataJSON: client_data_json, authenticatorData: Triauth::Helpers.array_buffer_to_base64url(trimmed) } } } }
          end

          ik = Triauth::IdentityKeys.new
          assert_equal true, ik.add("device[1/1]:#{john_key[:public]}", { type: 'webauthn-es256' })

          # Controls: UP=1 verifies, with or without UV
          signature, unsigned_data = mk_assertion.call(0x01).values_at(:signature, :unsignedData)
          assert ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'UP=1 assertion must verify'

          signature, unsigned_data = mk_assertion.call(0x05).values_at(:signature, :unsignedData)
          assert ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'UP=1|UV=1 assertion must verify'

          # UP=0 - a CTAP-level "silent" assertion is rejected even though correctly signed
          signature, unsigned_data = mk_assertion.call(0x00).values_at(:signature, :unsignedData)
          assert_equal false, ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'UP=0 (silent) assertion must be rejected'

          # UV without UP - still rejected (user presence is the mandated baseline)
          signature, unsigned_data = mk_assertion.call(0x04).values_at(:signature, :unsignedData)
          assert_equal false, ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'UV=1 without UP must be rejected'

          # authenticatorData shorter than 37 bytes (rpIdHash + flags + signCount) - rejected by the length guard
          signature, unsigned_data = mk_assertion.call(0x01, 36).values_at(:signature, :unsignedData)
          assert_equal false, ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'authenticatorData < 37 bytes must be rejected'
        end

        it 'validates the uv option fail-closed and enforces the User Verified (UV) flag for uv=required keys' do
          john_key = identities[:john][:devices][0][:keys][0]
          message = 'uv-option-test-message'

          mk_assertion = lambda do |flags_byte|
            auth_data = ("\xAA".b * 32) + [flags_byte].pack('C') + ("\x00".b * 4)

            client_data_json = JSON.generate({ type: 'webauthn.get', challenge: Triauth::Helpers.sha256(message), origin: 'https://triauthdemo.org', crossOrigin: false })

            cdj_hash = OpenSSL::Digest::SHA256.digest(Triauth::Helpers.string_to_utf8_bytes(client_data_json))
            payload = auth_data + cdj_hash
            private_key = SignerStub.from_jwk(john_key[:private]).private_keys[0]
            signature = Triauth::Helpers.array_buffer_to_base64url(OpenSSL::ASN1.decode(private_key.sign('SHA256', payload)).value.map { |i| i.value.to_s(2).rjust(32, "\x00".b) }.join)

            { signature: signature, unsignedData: { sig: { '0': { clientDataJSON: client_data_json, authenticatorData: Triauth::Helpers.array_buffer_to_base64url(auth_data) } } } }
          end

          # uv accepts only the literal 'required' - any other value taints the keyGroup (fail closed,
          # a typo must not silently drop the user verification requirement)
          ik = Triauth::IdentityKeys.new
          assert_equal false, ik.add("device[1/1]:#{john_key[:public]}", { type: 'webauthn-es256', uv: 'reuired' }), 'a mistyped uv value must not be accepted'
          assert_equal true, ik.key_groups[:device][:tainted], 'a mistyped uv value must taint the keyGroup'

          # uv on a non-webauthn key is unenforceable - taints as well
          ik = Triauth::IdentityKeys.new
          assert_equal false, ik.add("device[1/1]:#{john_key[:public]}", { uv: 'required' }), 'uv=required on a non-webauthn (default es256) key must not be accepted'
          assert_equal true, ik.key_groups[:device][:tainted], 'uv=required on a non-webauthn key must taint the keyGroup'

          ik = Triauth::IdentityKeys.new
          assert_equal false, ik.add("device[1/1]:#{john_key[:public]}", { type: 'ed25519', uv: 'required' }), 'uv=required on an ed25519 key must not be accepted'
          assert_equal true, ik.key_groups[:device][:tainted], 'uv=required on an ed25519 key must taint the keyGroup'

          # uv=required on a webauthn key is valid; assertions verify only with the UV flag set
          ik = Triauth::IdentityKeys.new
          assert_equal true, ik.add("device[1/1]:#{john_key[:public]}", { type: 'webauthn-es256', uv: 'required' })
          assert_equal true, ik.key_groups[:device][:valid]

          signature, unsigned_data = mk_assertion.call(0x05).values_at(:signature, :unsignedData) # UP|UV
          assert ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'UP=1|UV=1 assertion must verify for a uv=required key'

          signature, unsigned_data = mk_assertion.call(0x01).values_at(:signature, :unsignedData) # UP only
          assert_equal false, ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'UV=0 assertion must be rejected for a uv=required key'
        end

        it 'rejects webauthn clientDataJSON carrying a lone surrogate - the encoder refuses it and the refusal is absorbed to false' do
          john_key = identities[:john][:devices][0][:keys][0]
          message = 'lone-surrogate-test-message'

          auth_data = ("\xAA".b * 32) + "\x01".b + ("\x00".b * 4) # UP set - every gate before the hash step passes

          # A JSON "\ud800" escape survives JSON.parse as an actual unpaired surrogate inside the
          # clientDataJSON string (attacker-reachable: unsignedMetadata sits outside the signed
          # payload). Such a string has no UTF-8 bytes, so no authenticator can ever have signed it.
          # (A Ruby string cannot hold a lone surrogate: its ill-formed encoding `ED A0 80` is the counterpart, refused by the `is_string` gate)
          lone_surrogate = "\xED\xA0\x80".dup.force_encoding('UTF-8')
          client_data_json = "{\"type\":\"webauthn.get\",\"challenge\":\"#{Triauth::Helpers.sha256(message)}\",\"origin\":\"https://triauthdemo.org\",\"crossOrigin\":false,\"x\":\"#{lone_surrogate}\"}"

          # Sign the U+FFFD-substituted spelling - the bytes a lossy encoder would hash. This pins
          # that not even a signature over the substitute verifies: the encoder refuses the string
          # outright instead of aliasing it onto substituted bytes.
          substituted = client_data_json.b.sub(lone_surrogate.b, "�".b).force_encoding(Encoding::UTF_8) # at the byte level: a `sub` on an invalid string raises
          cdj_hash = OpenSSL::Digest::SHA256.digest(Triauth::Helpers.string_to_utf8_bytes(substituted))
          payload = auth_data + cdj_hash
          private_key = SignerStub.from_jwk(john_key[:private]).private_keys[0]
          signature = Triauth::Helpers.array_buffer_to_base64url(OpenSSL::ASN1.decode(private_key.sign('SHA256', payload)).value.map { |i| i.value.to_s(2).rjust(32, "\x00".b) }.join)

          unsigned_data = { sig: { '0': { clientDataJSON: client_data_json, authenticatorData: Triauth::Helpers.array_buffer_to_base64url(auth_data) } } }

          ik = Triauth::IdentityKeys.new
          assert_equal true, ik.add("device[1/1]:#{john_key[:public]}", { type: 'webauthn-es256' })

          # Resolves to false - the refusal never escapes the verifier as a throw
          assert_equal false, ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data)
        end

        # A fixed OKP/Ed25519 fixture pair; `public` is the 32-byte raw public key (base64url) as published in DNS
        ed25519_key = {
          public: 'Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0',
          private: { kty: 'OKP', crv: 'Ed25519', d: '-_UnNRraY7oJRq-G3bKgtnbM9y1AhAoj0zjAYr810yM', x: 'Kq4Z_SEEl9c-CCVbl3DKjPJeIN3NHGuYgrz7lhL3ue0' }
        }

        it 'validates ed25519 signatures' do
          message = 'ed25519-test-message'

          ik = Triauth::IdentityKeys.new
          assert_equal true, ik.add("device[1/1]:#{ed25519_key[:public]}", { type: 'ed25519' })
          assert_equal true, ik.key_groups[:device][:valid]
          assert_equal 1, ik.count

          signer_stub = SignerStub.from_jwk(ed25519_key[:private])
          signature, = signer_stub.sign(message)

          verify_result = ik.verify(message, [signature], { mode: 'auth' })
          assert verify_result
          assert_equal 'device', verify_result[:name]
          assert_equal true, verify_result[:keys][0][:verified]
          assert_equal false, verify_result[:keys][0][:skipped]

          verify_result = ik.verify("#{message}z", [signature], { mode: 'auth' })
          assert_equal false, verify_result, 'should not verify non-matching messages'

          verify_result = ik.verify(message, ["#{signature}a"], { mode: 'auth' })
          assert_equal false, verify_result, 'should not verify mangled signatures'
        end

        it 'verifies mixed-type keyGroups (es256 + ed25519)' do
          john_key = identities[:john][:devices][0][:keys][0]
          message = 'mixed-keygroup-test-message'

          ik = Triauth::IdentityKeys.new
          assert_equal true, ik.add("device[1/2]:#{john_key[:public]}", { type: 'es256' })
          assert_equal true, ik.add("device[2/2]:#{ed25519_key[:public]}", { type: 'ed25519' })
          assert_equal true, ik.key_groups[:device][:valid]

          es256_signature, = SignerStub.from_jwk(john_key[:private]).sign(message)
          ed25519_signature, = SignerStub.from_jwk(ed25519_key[:private]).sign(message)

          verify_result = ik.verify(message, [es256_signature, ed25519_signature], { mode: 'auth' })
          assert verify_result, 'a mixed group must verify when signatures for all keys are present'
          assert_equal true, verify_result[:keys][0][:verified]
          assert_equal true, verify_result[:keys][1][:verified]

          verify_result = ik.verify(message, [es256_signature], { mode: 'auth' })
          assert_equal false, verify_result, 'a missing ed25519 signature must fail the whole group'

          verify_result = ik.verify(message, [ed25519_signature], { mode: 'auth' })
          assert_equal false, verify_result, 'a missing es256 signature must fail the whole group'
        end

        it 'does not verify es256 key material published as type=ed25519' do
          john_key = identities[:john][:devices][0][:keys][0]
          message = 'wrong-key-material-test-message'

          ik = Triauth::IdentityKeys.new
          # The 65-byte P-256 key passes add() (key length is not type-checked there) ...
          assert_equal true, ik.add("device[1/1]:#{john_key[:public]}", { type: 'ed25519' })
          assert_equal true, ik.key_groups[:device][:valid]

          # ... but the raw Ed25519 import requires exactly 32 bytes, so no verifier can be
          # built for the key, and verification must fail without throwing
          signature, = SignerStub.from_jwk(john_key[:private]).sign(message)
          assert_equal false, ik.verify(message, [signature], { mode: 'auth' })
        end

        it 'ed25519 verifier returns false (not throws) on malformed verify() input' do
          verifier = Triauth::Verifiers::Ed25519.from_publishable_key(ed25519_key[:public])
          assert verifier, 'verifier must be built from a valid 32-byte raw public key'

          # `verifier.verify('some-message', null)` passes two arguments in triauth-js; the four of the verifier contract here
          assert_equal false, verifier.verify('some-message', nil, {}, {}), 'a non-string signature must yield false, not an exception'
        end

        it 'the WebAuthn base verifier is algorithm-agnostic and fails closed when used directly' do
          john_key = identities[:john][:devices][0][:keys][0]

          # No credential algorithm bound on the base class - fromPublishableKey must resolve to null...
          assert_nil Triauth::Verifiers::WebAuthn.from_publishable_key(john_key[:public])

          # ...and a directly-constructed instance must fail verification, not throw
          es256_verifier = Triauth::Verifiers::WebAuthnEs256.from_publishable_key(john_key[:public])
          assert es256_verifier, 'the concrete ES256 subclass must build fine from the same key'
          base_verifier = Triauth::Verifiers::WebAuthn.new(es256_verifier.public_key)
          assert_equal false, base_verifier.verify('some-message', 'AAAA', {}, {})
        end

        it 'validates webauthn-ed25519 signatures (incl. uv=required UV-flag enforcement)' do
          message = 'webauthn-ed25519-test-message'

          # Mint a fresh, correctly Ed25519-signed assertion with the given flags byte, so that a
          # rejection can only come from the WebAuthn-level checks - not from the crypto verification.
          mk_assertion = lambda do |flags_byte|
            auth_data = ("\xAA".b * 32) + [flags_byte].pack('C') + ("\x00".b * 4) # arbitrary rpIdHash (not checked - the key is pinned in DNS); bytes 33-36 (signCount) left as 0

            client_data_json = JSON.generate({ type: 'webauthn.get', challenge: Triauth::Helpers.sha256(message), origin: 'https://triauthdemo.org', crossOrigin: false })

            cdj_hash = OpenSSL::Digest::SHA256.digest(Triauth::Helpers.string_to_utf8_bytes(client_data_json))
            payload = auth_data + cdj_hash
            private_key = SignerStub.from_jwk(ed25519_key[:private]).private_keys[0]
            signature = Triauth::Helpers.array_buffer_to_base64url(private_key.sign(nil, payload))

            { signature: signature, unsignedData: { sig: { '0': { clientDataJSON: client_data_json, authenticatorData: Triauth::Helpers.array_buffer_to_base64url(auth_data) } } } }
          end

          # A UP=1 assertion backed by the ed25519 key verifies
          ik = Triauth::IdentityKeys.new
          assert_equal true, ik.add("device[1/1]:#{ed25519_key[:public]}", { type: 'webauthn-ed25519' })
          assert_equal true, ik.key_groups[:device][:valid]

          signature, unsigned_data = mk_assertion.call(0x01).values_at(:signature, :unsignedData)
          verify_result = ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data)
          assert verify_result, 'UP=1 webauthn-ed25519 assertion must verify'
          assert_equal true, verify_result[:keys][0][:verified]

          assert_equal false, ik.verify("#{message}z", [signature], { mode: 'auth' }, {}, unsigned_data), 'non-matching message must not verify'
          assert_equal false, ik.verify(message, ["#{signature[0...-2]}qq"], { mode: 'auth' }, {}, unsigned_data), 'mangled signature must not verify'

          # UP=0 (CTAP-level silent assertion) is rejected by the inherited WebAuthn-level check
          signature, unsigned_data = mk_assertion.call(0x00).values_at(:signature, :unsignedData)
          assert_equal false, ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'UP=0 (silent) assertion must be rejected'

          # es256 (65-byte) key material on a webauthn-ed25519 record cannot build a verifier - fail closed
          john_key = identities[:john][:devices][0][:keys][0]
          ik_wrong = Triauth::IdentityKeys.new
          assert_equal true, ik_wrong.add("device[1/1]:#{john_key[:public]}", { type: 'webauthn-ed25519' })
          signature, unsigned_data = mk_assertion.call(0x01).values_at(:signature, :unsignedData)
          assert_equal false, ik_wrong.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'es256 key material must not verify as webauthn-ed25519'

          # uv=required is valid on webauthn-ed25519 (a webauthn-* type) and enforces the UV flag
          ik = Triauth::IdentityKeys.new
          assert_equal true, ik.add("device[1/1]:#{ed25519_key[:public]}", { type: 'webauthn-ed25519', uv: 'required' })
          assert_equal true, ik.key_groups[:device][:valid]

          signature, unsigned_data = mk_assertion.call(0x05).values_at(:signature, :unsignedData) # UP|UV
          assert ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'UP=1|UV=1 assertion must verify for a uv=required webauthn-ed25519 key'

          signature, unsigned_data = mk_assertion.call(0x01).values_at(:signature, :unsignedData) # UP only
          assert_equal false, ik.verify(message, [signature], { mode: 'auth' }, {}, unsigned_data), 'UV=0 assertion must be rejected for a uv=required webauthn-ed25519 key'
        end
      end
    end
  end
end

TestInternals.identity_keys if __FILE__ == $PROGRAM_NAME
