# frozen_string_literal: true

require_relative '../setup'

module TestInternals
  def self.protocol
    describe 'protocol.js constants' do
      it 'pins the envelope vocabulary' do
        assert_equal 1, Triauth::Protocol::VERSION
        assert_equal 'v1', Triauth::Protocol::VERSION_TOKEN
        assert_equal '|', Triauth::Protocol::WRAPPER
        assert_equal ';', Triauth::Protocol::DELIMITER
        assert_equal '._at.', Triauth::Protocol::AT_MARKER
      end

      it 'pins the private-mode label length' do
        assert_equal 10, Triauth::Protocol::PRIVATE_LABEL_LENGTH
      end

      it 'pins the scope keywords: any (the sole-entry spelling covering every service host) and none (reserved, never valid)' do
        assert_equal 'any', Triauth::Protocol::SCOPE_ANY
        assert_equal 'none', Triauth::Protocol::SCOPE_NONE
      end

      it 'keeps FLOWS sorted and frozen' do
        assert_equal %w[attest auth ping sign stamp], Triauth::Protocol::FLOWS.dup
        assert Triauth::Protocol::FLOWS.frozen?
      end

      describe 'FLOWS_USE_REGEXP' do
        it 'accepts single flows and comma-joined flow lists' do
          Triauth::Protocol::FLOWS.each { |flow| assert Triauth::Protocol::FLOWS_USE_REGEXP.match?(flow), flow }
          assert Triauth::Protocol::FLOWS_USE_REGEXP.match?('auth,sign')
          assert Triauth::Protocol::FLOWS_USE_REGEXP.match?(Triauth::Protocol::FLOWS.join(','))
        end

        it 'rejects the empty string, unknown flows, and malformed lists' do
          ['', 'bogus', 'auth,', ',auth', 'auth,,sign', 'auth sign', 'AUTH', 'auth,bogus'].each do |bad|
            refute Triauth::Protocol::FLOWS_USE_REGEXP.match?(bad), bad.inspect
          end
        end
      end
    end
  end
end

TestInternals.protocol if __FILE__ == $PROGRAM_NAME
