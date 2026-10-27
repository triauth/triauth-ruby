# frozen_string_literal: true

require 'openssl'

# The JS file defines `class Signer` and exports it as the default, which every test imports as `SignerStub`;
# the class carries that name here.
class SignerStub
  # @return [Array<OpenSSL::PKey::PKey>] the private keys (the port of `privateCryptoKeys`)
  attr_reader :private_keys

  # Derives the Web Crypto import parameters from the JWK itself,
  # so that both EC (P-256) and OKP (Ed25519) fixture keys can be used.
  def self.algorithm_for_jwk(jwk_private_key)
    if jwk_private_key[:kty] == 'OKP' && jwk_private_key[:crv] == 'Ed25519'
      return { name: 'Ed25519' }
    end

    return { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } }
  end

  def self.from_jwk(jwk_private_keys, options = nil)
    jwk_private_keys = [jwk_private_keys] if !jwk_private_keys.is_a?(Array)
    private_crypto_keys = []

    jwk_private_keys.each do |jwk_private_key|
      algorithm = options.nil? ? SignerStub.algorithm_for_jwk(jwk_private_key) : options
      # `crypto.subtle.importKey('jwk', ...)`: OpenSSL has no JWK import, so the key is built from the JWK's fields -
      # an Ed25519 key through its PKCS#8 DER, an EC key through the SEC1 `ECPrivateKey` DER
      crypto_key =
        if algorithm[:name] == 'Ed25519'
          OpenSSL::PKey.read(['302e020100300506032b657004220420'].pack('H*') + Triauth::Helpers.base64url_to_uint8(jwk_private_key[:d]))
        else
          d = Triauth::Helpers.base64url_to_uint8(jwk_private_key[:d])
          x = Triauth::Helpers.base64url_to_uint8(jwk_private_key[:x])
          y = Triauth::Helpers.base64url_to_uint8(jwk_private_key[:y])
          ec_private_key = OpenSSL::ASN1::Sequence(
            [
              OpenSSL::ASN1::Integer(1),
              OpenSSL::ASN1::OctetString(d),
              OpenSSL::ASN1::ObjectId('prime256v1', 0, :EXPLICIT),
              OpenSSL::ASN1::BitString("\x04".b + x + y, 1, :EXPLICIT)
            ]
          )
          OpenSSL::PKey::EC.new(ec_private_key.to_der)
        end
      private_crypto_keys.push(crypto_key)
    end

    return SignerStub.new(private_crypto_keys)
  end

  def self.from_device_keys(keys)
    return SignerStub.from_jwk(keys.map { |k| k[:private] })
  end

  def self.sign_using_device_keys(keys)
    # the cryptoSigner receives the payload and the mutable unsignedMetadata reference
    return lambda do |payload, _unsigned_metadata_ref = nil|
      signer = SignerStub.from_device_keys(keys)
      signer.sign(payload)
    end
  end

  def initialize(private_keys)
    @private_keys = private_keys
  end

  def sign(message)
    data = Triauth::Helpers.string_to_utf8_bytes(message)

    signatures = []

    @private_keys.each do |private_key|
      # `crypto.subtle.sign` yields the raw signature: the 64 raw bytes for Ed25519, `r || s` for ECDSA - OpenSSL signs
      # to the DER `SEQUENCE { INTEGER r, INTEGER s }`, converted back to raw here (the inverse of the verifier's `raw_to_der`)
      crypto_sig =
        if private_key.oid == 'ED25519'
          private_key.sign(nil, data)
        else
          der = private_key.sign('SHA256', data)
          OpenSSL::ASN1.decode(der).value.map { |i| i.value.to_s(2).rjust(32, "\x00".b) }.join
        end

      signatures.push(Triauth::Helpers.array_buffer_to_base64url(crypto_sig))
    end

    return signatures
  end
end
