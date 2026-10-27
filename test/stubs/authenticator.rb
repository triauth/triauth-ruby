# frozen_string_literal: true

require 'json'

# Plays the Triauth Authenticator's part of the challenge-response flow in tests. The authenticator receives only the
# public part of the challenge that stage 1 returns, and it seals the response to that challenge's `ek`.
class AuthenticatorStub
  # A session key as `Triauth.authenticate` returns it, for the flows that follow a sign-in
  SESSION_KEY = '59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8'

  # The challenge as the authenticator receives it: the stored challenge before its `.` and decryption key
  def self.public_challenge(stored_challenge)
    return stored_challenge.split('.', -1)[0]
  end

  # A stored challenge re-encoded from edited challenge data, with the decryption key of the original kept
  def self.reencode(stored_challenge, data)
    decryption_key = stored_challenge.split('.', -1)[1]
    return Triauth::Helpers.string_to_base64url(JSON.generate(data)) + (decryption_key.nil? ? '' : ".#{decryption_key}")
  end

  # A stored challenge for hand-built challenge data: the data gets a fresh `ek`, and the stored form keeps its key
  def self.store(data)
    encryption_key, decryption_key = Triauth::ResponseCipher.generate_key_pair.values_at(:encryptionKey, :decryptionKey)
    # `{...data, ek: encryptionKey}`: `merge` keeps the position of an existing `ek`, as the spread does
    return "#{Triauth::Helpers.string_to_base64url(JSON.generate(data.merge({ ek: encryption_key })))}.#{decryption_key}"
  end

  # The response as the authenticator sends it, sealed to the challenge's `ek`. A `false` denial, a non-string
  # envelope, a challenge that does not decode, or a challenge without `ek` (which the authenticator refuses) passes
  # the envelope through unchanged, so tests can show that stage 3 refuses it.
  def self.seal(stored_challenge, envelope)
    if !Triauth::Helpers.is_string(stored_challenge) || !Triauth::Helpers.is_string(envelope) || envelope == 'false'
      return envelope
    end

    begin
      data = Triauth::Challenge.from_string(AuthenticatorStub.public_challenge(stored_challenge)).data
      ek = data[:ek]
    rescue StandardError
      return envelope
    end

    # `ek === undefined` is the member absent (`data.key?(:ek)`): a present `"ek": null` goes on to seal and fails, as JS `seal(null, ...)` does
    return !data.key?(:ek) ? envelope : Triauth::ResponseCipher.seal(ek, envelope)[:sealedResponse]
  end
end
