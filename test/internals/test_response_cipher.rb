# frozen_string_literal: true

require_relative '../setup'
require 'openssl'

module TestInternals
  def self.response_cipher
    # RFC 9180, appendix A.3.1: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, base mode, sequence number 0
    # (`VECTOR`, `ENVELOPE` and the file-scope helpers are locals here: a constant cannot be assigned inside a method body)
    vector = {
      info: '4f6465206f6e2061204772656369616e2055726e',
      pkEm: '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4',
      skEm: '4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb',
      pkRm: '04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0',
      skRm: 'f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2',
      pt: '4265617574792069732074727574682c20747275746820626561757479',
      aad: '436f756e742d30',
      ct: '5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434'
    }

    # `P256` (the Web Crypto import parameters) has no counterpart: the curve is named inside the SEC1 DER of `vector_keys`
    envelope = '|auth;john@triauthdemo.org;;https://example.com/;v1;1787224766683;;;S8lEY3KOYs9gsSpCJ8YnbnKHVCJcT0dXRREZCAgfIR_3dqkW3S9eUcfQZc6q2HD2sy56LwndOoSbcGyO2ZbUnw|'

    hex_to_bytes = ->(hex) { [hex].pack('H*') }
    bytes_to_hex = ->(bytes) { bytes.unpack1('H*') }
    b64u = ->(bytes) { Triauth::Helpers.array_buffer_to_base64url(bytes) }

    # A P-256 key pair from the vector's raw keys, as Web Crypto imports it: OpenSSL has no JWK import, so the private
    # key is built from `d`, `x` and `y` through the SEC1 `ECPrivateKey` DER (the construction of `test/stubs/signer.rb`;
    # `usages` has no counterpart), and the one OpenSSL key holds both halves, so `privateKey` and `publicKey` are the
    # same object
    vector_keys = lambda do |pk_hex, sk_hex|
      pk = hex_to_bytes.call(pk_hex)
      ec_private_key = OpenSSL::ASN1::Sequence(
        [
          OpenSSL::ASN1::Integer(1),
          OpenSSL::ASN1::OctetString(hex_to_bytes.call(sk_hex)),
          OpenSSL::ASN1::ObjectId('prime256v1', 0, :EXPLICIT),
          OpenSSL::ASN1::BitString("\x04".b + pk[1, 32] + pk[33..], 1, :EXPLICIT)
        ]
      )
      key = OpenSSL::PKey::EC.new(ec_private_key.to_der)
      return { privateKey: key, publicKey: key }
    end

    # Replaces one base64url character at the given index with a different one
    flip = ->(string, index) { string[0...index] + (string[index] == 'A' ? 'B' : 'A') + string[(index + 1)..] }

    # the JS `rejects(promise)`: true when the call in the block raises (any `StandardError`), false when it returns
    rejects = lambda do |&blk|
      blk.call
      return false
    rescue StandardError
      return true
    end

    describe 'Triauth.ResponseCipher' do
      it 'reproduces the RFC 9180 A.3.1 encapsulated key and ciphertext' do
        ephemeral = vector_keys.call(vector[:pkEm], vector[:skEm])
        enc, ct = Triauth::ResponseCipher.seal_base(hex_to_bytes.call(vector[:pkRm]), hex_to_bytes.call(vector[:info]), hex_to_bytes.call(vector[:aad]), hex_to_bytes.call(vector[:pt]), ephemeral[:privateKey]).values_at(:enc, :ct)

        assert_equal vector[:pkEm], bytes_to_hex.call(enc)
        assert_equal vector[:ct], bytes_to_hex.call(ct)
      end

      it 'opens the RFC 9180 A.3.1 ciphertext with the recipient key' do
        recipient = vector_keys.call(vector[:pkRm], vector[:skRm])
        pt = Triauth::ResponseCipher.open_base(hex_to_bytes.call(vector[:pkEm]), recipient[:privateKey], hex_to_bytes.call(vector[:pkRm]), hex_to_bytes.call(vector[:info]), hex_to_bytes.call(vector[:aad]), hex_to_bytes.call(vector[:ct]))[:pt]

        assert_equal vector[:pt], bytes_to_hex.call(pt)
      end

      it 'mints key pairs in the wire format: an 87-character uncompressed point and a 43-character scalar' do
        encryption_key, decryption_key = Triauth::ResponseCipher.generate_key_pair.values_at(:encryptionKey, :decryptionKey)

        assert_match(/\A[A-Za-z0-9_-]{87}\z/, encryption_key)
        assert_equal 0x04, Triauth::Helpers.base64url_to_uint8(encryption_key).getbyte(0)
        assert_match(/\A[A-Za-z0-9_-]{43}\z/, decryption_key)
      end

      it 'seals a response that opens with the key pair, as `<enc>.<ciphertext>`, and gives both sides the same session key' do
        encryption_key, decryption_key = Triauth::ResponseCipher.generate_key_pair.values_at(:encryptionKey, :decryptionKey)
        sealed, session_key = Triauth::ResponseCipher.seal(encryption_key, envelope).values_at(:sealedResponse, :sessionKey)
        opened = Triauth::ResponseCipher.open(encryption_key, decryption_key, sealed)

        assert_match(/\A[A-Za-z0-9_-]{87}\.[A-Za-z0-9_-]{22,}\z/, sealed)
        refute_includes sealed, 'john', 'the sealed response does not show the identifier'
        assert_equal envelope, opened[:response]
        assert_match(/\A[A-Za-z0-9_-]{43}\z/, session_key)
        assert_equal session_key, opened[:sessionKey]
      end

      it 'round-trips UTF-8 beyond Latin-1' do
        encryption_key, decryption_key = Triauth::ResponseCipher.generate_key_pair.values_at(:encryptionKey, :decryptionKey)
        text = "|auth;Привет \u{1F389}|"

        sealed_response = Triauth::ResponseCipher.seal(encryption_key, text)[:sealedResponse]

        assert_equal text, Triauth::ResponseCipher.open(encryption_key, decryption_key, sealed_response)[:response]
      end

      it 'uses a fresh ephemeral key, and so a fresh session key, for every seal' do
        encryption_key = Triauth::ResponseCipher.generate_key_pair[:encryptionKey]
        first = Triauth::ResponseCipher.seal(encryption_key, envelope)
        second = Triauth::ResponseCipher.seal(encryption_key, envelope)

        refute_equal first[:sealedResponse].split('.', -1)[0], second[:sealedResponse].split('.', -1)[0]
        refute_equal first[:sealedResponse], second[:sealedResponse]
        refute_equal first[:sessionKey], second[:sessionKey]
      end

      it 'refuses a ciphertext or encapsulated key that was changed in transit' do
        encryption_key, decryption_key = Triauth::ResponseCipher.generate_key_pair.values_at(:encryptionKey, :decryptionKey)
        sealed = Triauth::ResponseCipher.seal(encryption_key, envelope)[:sealedResponse]

        assert(rejects.call { Triauth::ResponseCipher.open(encryption_key, decryption_key, flip.call(sealed, sealed.length - 5)) }, 'tampered ciphertext')
        assert(rejects.call { Triauth::ResponseCipher.open(encryption_key, decryption_key, flip.call(sealed, 40)) }, 'tampered encapsulated key')
      end

      it 'refuses a response sealed to another key pair' do
        intended = Triauth::ResponseCipher.generate_key_pair
        other = Triauth::ResponseCipher.generate_key_pair
        sealed = Triauth::ResponseCipher.seal(intended[:encryptionKey], envelope)[:sealedResponse]

        assert(rejects.call { Triauth::ResponseCipher.open(other[:encryptionKey], other[:decryptionKey], sealed) })
        assert(rejects.call { Triauth::ResponseCipher.open(intended[:encryptionKey], other[:decryptionKey], sealed) })
      end

      it 'refuses a malformed sealed response' do
        encryption_key, decryption_key = Triauth::ResponseCipher.generate_key_pair.values_at(:encryptionKey, :decryptionKey)
        sealed = Triauth::ResponseCipher.seal(encryption_key, envelope)[:sealedResponse]
        enc, ct = sealed.split('.', -1)

        [envelope, enc, "#{enc}.", ".#{ct}", "#{sealed}.#{ct}", '', 'false', 123].each do |malformed|
          assert(rejects.call { Triauth::ResponseCipher.open(encryption_key, decryption_key, malformed) }, malformed.to_s[0, 20])
        end
      end

      it 'refuses to seal to an encryption key that is not an uncompressed P-256 point' do
        encryption_key = Triauth::ResponseCipher.generate_key_pair[:encryptionKey]
        point = Triauth::Helpers.base64url_to_uint8(encryption_key)
        compressed = b64u.call("#{(0x02 + (point.getbyte(64) & 1)).chr}#{point[1, 32]}".b)
        off_curve = b64u.call("\x04".b + ("\x01".b * 64))

        [compressed, off_curve, encryption_key[0...-2], ''].each do |invalid|
          assert(rejects.call { Triauth::ResponseCipher.seal(invalid, envelope) }, invalid[0, 12])
        end
      end

      it 'validates the sealed form and its length before any crypto (invalid_response)' do
        encryption_key = Triauth::ResponseCipher.generate_key_pair[:encryptionKey]
        sealed = Triauth::ResponseCipher.seal(encryption_key, envelope)[:sealedResponse]
        enc = sealed.split('.', -1)[0]

        assert_equal true, Triauth::Validator.validate_sealed_response(sealed)[:valid]

        [envelope, enc, "#{enc}.#{'A' * 21}", "#{sealed}.x", "#{'A' * 86}.#{'A' * 22}", "#{enc}.#{'A' * 30_000}", nil, 123].each do |invalid|
          result = Triauth::Validator.validate_sealed_response(invalid)
          assert_equal false, result[:valid], invalid.to_s[0, 20]
          assert_equal 'invalid_response', result[:errors][0][:code]
        end
      end

      # The test below exists only in the port: it pins the guards the OpenSSL binding
      # needs around AES-GCM and the Integer gate of `export`.
      describe 'Triauth.ResponseCipher (port-only)' do
        it 'seals an empty plaintext to the tag alone and opens it back, refuses a ciphertext shorter than the tag, and admits only an Integer export length from 1 to 32' do
          recipient = vector_keys.call(vector[:pkRm], vector[:skRm])
          pk_rm = hex_to_bytes.call(vector[:pkRm])
          info = hex_to_bytes.call(vector[:info])
          aad = hex_to_bytes.call(vector[:aad])
          sealed = Triauth::ResponseCipher.seal_base(pk_rm, info, aad, ''.b)
          assert_equal 65, sealed[:enc].bytesize
          assert_equal 16, sealed[:ct].bytesize
          opened = Triauth::ResponseCipher.open_base(sealed[:enc], recipient[:privateKey], pk_rm, info, aad, sealed[:ct])
          assert_equal ''.b, opened[:pt]
          assert_equal sealed[:exporterSecret], opened[:exporterSecret]
          # a ciphertext shorter than the tag is refused before the decryption (OpenSSL would check a truncated tag)
          err = assert_raises(TypeError) { Triauth::ResponseCipher.open_base(sealed[:enc], recipient[:privateKey], pk_rm, info, aad, sealed[:ct][0, 15]) }
          assert_equal 'Malformed ciphertext', err.message
          # a tampered tag-only ciphertext does not authenticate
          tampered = sealed[:ct].dup
          tampered.setbyte(0, tampered.getbyte(0) ^ 1)
          assert_raises(OpenSSL::Cipher::CipherError) { Triauth::ResponseCipher.open_base(sealed[:enc], recipient[:privateKey], pk_rm, info, aad, tampered) }
          # `export`: an Integer from 1 to 32 (a Float such as 32.0, an integer in JS, is refused here; no caller passes one)
          assert_equal 1, Triauth::ResponseCipher.export(sealed[:exporterSecret], 'ctx'.b, 1).bytesize
          assert_equal 32, Triauth::ResponseCipher.export(sealed[:exporterSecret], 'ctx'.b, 32).bytesize
          [0, 33, 32.0, '32', nil].each do |length|
            err = assert_raises(RangeError) { Triauth::ResponseCipher.export(sealed[:exporterSecret], 'ctx'.b, length) }
            assert_equal 'Invalid export length', err.message
          end
        end
      end
    end
  end
end

TestInternals.response_cipher if __FILE__ == $PROGRAM_NAME
