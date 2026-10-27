# frozen_string_literal: true

require_relative '../setup'

module TestInternals
  def self.config
    describe 'Config override guard (invalid_config)' do
      # Every config-consuming public method runs the same guard. The challenge-response methods
      # (authenticate/ping/attest/sign/stamp) share it via ChallengeResponseFlow.perform; check/verify/whois
      # each carry their own. validate is intentionally excluded - it ignores config entirely.
      opts = { identifier: 'john@triauthdemo.org', callbackUrl: 'https://example.org/cb' }
      # (`Promise.all([...])`: the eight calls in sequence, their results in the same order)
      call_with = lambda do |config|
        [
          Triauth.authenticate(opts, config),
          Triauth.ping(opts, config),
          Triauth.attest(opts, config),
          Triauth.sign(opts, config),
          Triauth.stamp(opts, config),
          Triauth.check({ identifier: 'john@triauthdemo.org', deviceTag: 'tag' }, config),
          Triauth.verify('message', 'signature', {}, config),
          Triauth.whois({ identifier: 'john@triauthdemo.org' }, config)
        ]
      end

      it 'KNOWN_CONFIG_KEYS is a frozen snapshot of the declared keys, and cid defaults to null' do
        assert Triauth::KNOWN_CONFIG_KEYS.frozen?, 'snapshot must be frozen'
        assert Triauth::KNOWN_CONFIG_KEYS.include?(:cid)
        assert Triauth::KNOWN_CONFIG_KEYS.include?(:requireSecure)
        assert_equal Triauth.config.keys.sort, Triauth::KNOWN_CONFIG_KEYS.sort
        assert_nil Triauth.config[:cid]
      end

      it 'rejects a per-call override carrying an unknown key (invalid_config) on every config-consuming method' do
        # `requireSecur` is a misspelling of `requireSecure` - without the guard it would be silently
        # ignored, leaving the caller believing DNSSEC was required when it was not.
        call_with.call({ requireSecur: true }).each do |r|
          assert_equal 'invalid_config', r.dig(:error, :code) # `r.error?.code`
          assert_equal 'Unrecognized configuration key', r.dig(:error, :message)
        end
      end

      # 'rejects a known key explicitly set to undefined (invalid_config), which would otherwise clobber its default' is not ported:
      # Ruby has one null, and a `nil` value follows the JS `null` branch of the guard (a dead branch)

      it 'accepts a valid override (no invalid_config - processing continues to its normal result)' do
        # verify is network-free, so this exercises the guard's accept path without DNS.
        r = Triauth.verify('m', 's', {}, { requireSecure: true, maximalAllowedClientClockDrift: 1000 })
        refute_equal 'invalid_config', r.dig(:error, :code)
      end

      it 'treats cid well: null / false / a string pass, undefined is rejected (invalid_config)' do
        refute_equal 'invalid_config', Triauth.verify('m', 's', {}, { cid: nil }).dig(:error, :code)
        refute_equal 'invalid_config', Triauth.verify('m', 's', {}, { cid: false }).dig(:error, :code)
        refute_equal 'invalid_config', Triauth.verify('m', 's', {}, { cid: 'corr-123' }).dig(:error, :code)
        # (the `cid: undefined` assertion is a dead branch: Ruby has one null, and `cid: nil` follows the JS `null` branch above)
      end

      it 'catches a typo introduced via global Triauth.config mutation, then recovers once cleaned up' do
        # Validating the *merged* config means a stray global key is caught on the very next call,
        # even with no per-call override at all.
        refute Triauth.config.key?(:requireSecur) # `!('requireSecur' in Triauth.config)`
        Triauth.config[:requireSecur] = true
        begin
          r = Triauth.verify('m', 's', {})
          assert_equal 'invalid_config', r.dig(:error, :code)
        ensure
          Triauth.config.delete(:requireSecur)
        end
        refute_equal 'invalid_config', Triauth.verify('m', 's', {}).dig(:error, :code)
      end

      it 'honors a logger override' do
        r1 = Triauth.verify('m', 's', {}, { logger: nil })
        refute_equal 'invalid_config', r1.dig(:error, :code)

        # `{ debug() {}, info() {}, warn() {}, error() {} }`: an object with the four no-op methods and no `spawn`
        custom = Class.new do
          def debug(*); end
          def info(*); end
          def warn(*); end
          def error(*); end
        end.new
        r2 = Triauth.verify('m', 's', {}, { logger: custom })
        refute_equal 'invalid_config', r2.dig(:error, :code)
      end

      it 'validate carries the same config override guard' do
        # unknown key -> invalid_config
        bad = Triauth.validate({ identifier: 'john@triauthdemo.org' }, { requireSecur: true })
        assert_equal false, bad[:valid]
        assert(bad[:errors].any? { |e| e[:code] == 'invalid_config' && e[:message] == 'Unrecognized configuration key' })

        # strict: a known key set to undefined is rejected too (JSON suites can't express undefined, so it lives here)
        # (dropped: Ruby has one null, and `requireSecure: nil` follows the JS `null` branch, which the guard accepts)

        # a valid override is accepted and object validation proceeds normally
        assert_equal true, Triauth.validate({ identifier: 'john@triauthdemo.org' }, { requireSecure: true })[:valid]

        # the objects guard still takes precedence over the config guard
        assert_equal 'invalid_arguments', Triauth.validate({ bogus: 1 }, { requireSecur: true })[:errors][0][:code]
      end
    end
  end
end

TestInternals.config if __FILE__ == $PROGRAM_NAME
