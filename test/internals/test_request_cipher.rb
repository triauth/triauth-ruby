# frozen_string_literal: true

require_relative '../setup'

module TestInternals
  def self.request_cipher
    # A fixed session key, and a challenge sealed under it once, so that the derivation of the request key stays the same
    # (`VECTOR`, `OTHER_KEY` and the file-scope helpers are locals here: a constant cannot be assigned inside a method body)
    vector = {
      sessionKey: '59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8',
      skid: 'wzI1sz3n1R4biw4FL_VJ3Q',
      challenge: 'eyJ0eXBlIjoicGluZyIsImlkZW50aWZpZXIiOiJqb2huQHRyaWF1dGhkZW1vLm9yZyJ9',
      sealed: 'P2Ba7MARsXQZNhKC.QPOC3-Co8j1POUCTnc-nRsvppsBp8f1i6vJU-NnjzLHkF9mX2O3jV93_WU2IXjT6ha8AX1q75oAQmaDTZUZ-kuJrwg'
    }

    other_key = 'A' * 43

    # Replaces one base64url character at the given index with a different one
    flip = ->(string, index) { string[0...index] + (string[index] == 'A' ? 'B' : 'A') + string[(index + 1)..] }

    # the JS `rejects(promise)`: true when the call in the block raises (any `StandardError`), false when it returns
    rejects = lambda do |&blk|
      blk.call
      return false
    rescue StandardError
      return true
    end

    describe 'Triauth.RequestCipher' do
      it 'opens the fixed vector, and computes its skid' do
        assert_equal vector[:challenge], Triauth::RequestCipher.open(vector[:sessionKey], vector[:sealed])
        assert_equal vector[:skid], Triauth::RequestCipher.skid(vector[:sessionKey])
      end

      it 'seals a challenge that opens under the same session key, as `<iv>.<ciphertext>`' do
        sealed = Triauth::RequestCipher.seal(vector[:sessionKey], vector[:challenge])

        assert_match(/\A[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}\z/, sealed)
        assert_equal vector[:challenge], Triauth::RequestCipher.open(vector[:sessionKey], sealed)
      end

      it 'uses a fresh IV for every seal' do
        first = Triauth::RequestCipher.seal(vector[:sessionKey], vector[:challenge])
        second = Triauth::RequestCipher.seal(vector[:sessionKey], vector[:challenge])

        refute_equal first.split('.', -1)[0], second.split('.', -1)[0]
      end

      it 'refuses a request that was changed in transit, or sealed under another session key' do
        assert(rejects.call { Triauth::RequestCipher.open(vector[:sessionKey], flip.call(vector[:sealed], 3)) }, 'changed IV')
        assert(rejects.call { Triauth::RequestCipher.open(vector[:sessionKey], flip.call(vector[:sealed], vector[:sealed].length - 3)) }, 'changed ciphertext')
        assert(rejects.call { Triauth::RequestCipher.open(other_key, vector[:sealed]) }, 'another session key')
      end

      it 'refuses a malformed sealed request' do
        iv, ct = vector[:sealed].split('.', -1)

        ['', iv, "#{iv}.", ".#{ct}", "#{vector[:sealed]}.x", "#{iv[1..]}.#{ct}", 123].each do |malformed|
          assert(rejects.call { Triauth::RequestCipher.open(vector[:sessionKey], malformed) }, malformed.to_s[0, 20])
        end
      end

      it 'gives a different skid for a different session key' do
        skid = Triauth::RequestCipher.skid(other_key)

        assert_match(/\A[A-Za-z0-9_-]{22}\z/, skid)
        refute_equal vector[:skid], skid
      end

      # The test below exists only in the port: it pins the guards the OpenSSL binding
      # needs around AES-GCM.
      describe 'Triauth.RequestCipher (port-only)' do
        it 'seals an empty challenge to the IV and the tag alone and opens it back, and refuses a ciphertext shorter than the tag' do
          sealed = Triauth::RequestCipher.seal(vector[:sessionKey], '')
          assert_match(/\A[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22}\z/, sealed)
          assert_equal '', Triauth::RequestCipher.open(vector[:sessionKey], sealed)
          iv = sealed.split('.', -1)[0]
          err = assert_raises(TypeError) { Triauth::RequestCipher.open(vector[:sessionKey], "#{iv}.#{Triauth::Helpers.array_buffer_to_base64url("\x00".b * 15)}") }
          assert_equal 'Malformed ciphertext', err.message
        end
      end
    end
  end
end

TestInternals.request_cipher if __FILE__ == $PROGRAM_NAME
