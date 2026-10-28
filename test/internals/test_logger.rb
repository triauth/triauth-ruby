# frozen_string_literal: true

require_relative '../setup'

module TestInternals
  def self.logger
    describe 'Triauth.Logger' do
      it 'Logs only messages with urgency equal or above to the set logLevel' do
        messages = []

        log = ->(*args) { messages.push(args) }

        output = Object.new
        output.define_singleton_method(:debug, &log)
        output.define_singleton_method(:info, &log)
        output.define_singleton_method(:warn, &log)
        output.define_singleton_method(:error, &log)
        logger = Triauth::Logger.new(output)

        4.times do |i|
          logger.log_level = %w[debug info warn error][i]

          4.times do |j|
            logger.public_send(%w[debug info warn error][j], j)
          end
        end

        assert_equal(
          [0, 1, 2, 3, 1, 2, 3, 2, 3, 3],
          messages.map { |e| e[2] }
        )
      end

      # Returns the `[cid:...]` segment of a single warn line, or nil when the logger emits no cid tag.
      cid_tag_of = lambda do |logger|
        captured = []
        noop = ->(*) {}
        out = Object.new
        out.define_singleton_method(:debug, &noop)
        out.define_singleton_method(:info, &noop)
        out.define_singleton_method(:warn) { |*a| captured.push(a) }
        out.define_singleton_method(:error, &noop)
        logger.output = out
        logger.log_level = 'warn'
        logger.warn('x')
        captured[0].find { |p| p.is_a?(String) && p.start_with?('[cid:') }
      end

      it 'spawn resolves cid: nullish autofills, false opts out, a string is used verbatim' do
        base = Triauth::Logger.new(nil, { prefix: '[t]' })

        # nullish (nil) -> a fresh id is minted
        assert_match(/\A\[cid:.+\]\z/, cid_tag_of.call(base.spawn(nil)))
        # `base.spawn(undefined)` has no counterpart: Ruby has one null

        # false -> explicit opt-out, no tag at all
        assert_nil cid_tag_of.call(base.spawn(false))

        # string -> used exactly
        assert_equal '[cid:corr-123]', cid_tag_of.call(base.spawn('corr-123'))
      end

      it 'spawn inherits the parent cid when its argument is nullish' do
        base = Triauth::Logger.new(nil, { prefix: '[t]', cid: 'parent' })
        assert_equal '[cid:parent]', cid_tag_of.call(base.spawn(nil))
      end
    end

    # The tests below exist only in the port: they pin the Ruby
    # semantics of the logging idioms and the port-only helpers, which no triauth-js test can cover.

    # An output stub whose four level methods append `[level, *args]` to `calls`.
    capturing_output = lambda do |calls|
      out = Object.new
      %i[debug info warn error].each do |level|
        out.define_singleton_method(level) { |*args| calls.push([level, *args]) }
      end
      out
    end

    describe 'Triauth.Logger (port-only)' do
      it 'tolerates a nil output at every level (the port of `this.output?.debug(...)`)' do
        logger = Triauth::Logger.new(nil, { logLevel: 'debug' })
        assert_nil logger.debug('x')
        assert_nil logger.info('x')
        assert_nil logger.warn('x')
        assert_nil logger.error('x')
      end

      it 'admits nothing for a logLevel outside debug/info/warn/error' do
        calls = []
        logger = Triauth::Logger.new(capturing_output.call(calls), { logLevel: 'silent' })
        logger.debug('x')
        logger.info('x')
        logger.warn('x')
        logger.error('x')
        assert_equal [], calls
      end

      it 'treats an empty logLevel and prefix as absent (the JS `||` defaults) and emits no tag for an empty cid (the JS `if (this.cid)`)' do
        calls = []
        logger = Triauth::Logger.new(capturing_output.call(calls), { logLevel: '', prefix: '', cid: '' })
        assert_equal 'warn', logger.log_level
        assert_equal '[triauth]', logger.prefix
        assert_equal '', logger.cid
        logger.warn('x')
        assert_equal [[:warn, '[triauth]', '[warn]', 'x']], calls
      end

      it 'spawn mints a fresh cid for a parent whose cid is empty, as the JS `this.cid || ...` does for every falsy cid' do
        base = Triauth::Logger.new(nil, { cid: '' })
        assert_match(/\A[0-9a-z]{8}\z/, base.spawn(nil).cid)
        assert_match(/\A[0-9a-z]{8}\z/, Triauth::Logger.new(nil, { cid: false }).spawn(nil).cid)
        assert_match(/\A[0-9a-z]{8}\z/, Triauth::Logger.new(nil).spawn(nil).cid)
        assert_equal 'parent', Triauth::Logger.new(nil, { cid: 'parent' }).spawn(nil).cid
        assert_equal '', base.spawn('').cid # an explicit '' argument is not nullish: used verbatim, as in JS
        assert_equal false, base.spawn(false).cid
      end
    end

    describe 'Triauth.Logger.CONSOLE (port-only)' do
      it 'writes debug and info lines to $stdout and warn and error lines to $stderr, Strings as they are and other values via inspect' do
        out, err = capture_io do
          Triauth::Logger::CONSOLE.debug('[triauth]', '[debug]', 'd', 1)
          Triauth::Logger::CONSOLE.info('[triauth]', '[info]', 'i', { k: 'v' })
          Triauth::Logger::CONSOLE.warn('[triauth]', '[warn]', 'w', nil)
          Triauth::Logger::CONSOLE.error('[triauth]', '[error]', 'e', [1, 2])
        end
        # Hash#inspect prints {k: "v"} from Ruby 3.4 on and {:k=>"v"} before it
        assert_equal "[triauth] [debug] d 1\n[triauth] [info] i #{{ k: 'v' }.inspect}\n", out
        assert_equal "[triauth] [warn] w nil\n[triauth] [error] e [1, 2]\n", err
      end
    end

    describe 'Triauth.Helpers.log (port-only)' do
      it 'calls the logger only when it is set and responds to the level (the port of `config.logger?.<level>?.(...)`)' do
        assert_nil Triauth::Helpers.log({ logger: nil }, :debug, 'x')

        calls = []
        partial = Object.new
        partial.define_singleton_method(:debug) do |*args|
          calls.push(args)
          :logged
        end
        config = { logger: partial }
        assert_nil Triauth::Helpers.log(config, :info, 'x')
        assert_equal :logged, Triauth::Helpers.log(config, :debug, 'x', { k: 'v' })
        assert_equal [['x', { k: 'v' }]], calls
      end
    end

    describe 'Triauth.Error (port-only)' do
      it "carries code, reason, message, data without cause, and ts; the cause is Ruby's own Exception#cause from the enclosing rescue" do
        err = nil
        begin
          begin
            raise 'inner'
          rescue StandardError
            raise Triauth::Error.new({ code: 'invalid_signature', reason: 'invalid', message: 'Invalid signature' }, { cause: 'stripped', k: 'v' })
          end
        rescue Triauth::Error => e
          err = e
        end
        assert_equal 'invalid_signature', err.code
        assert_equal 'invalid', err.reason
        assert_equal 'Invalid signature', err.message
        assert_equal({ k: 'v' }, err.data)
        assert_equal 'inner', err.cause.message
        assert_kind_of Time, err.ts
        assert_equal({}, Triauth::Error.new({ code: 'internal_error', message: 'Internal error' }).data)
        assert_nil Triauth::Error.new({ code: 'internal_error', message: 'Internal error' }).reason # the JS `undefined` of an error without a reason
      end

      it 'process logs validation errors at info, other Triauth::Errors at warn, anything else at error naming the triauth-ruby issue tracker, and returns the {error: {code, reason?, message}} shape' do
        calls = []
        config = { logger: capturing_output.call(calls) }

        validation = Triauth::Error.new({ code: 'invalid_challenge', reason: 'invalid', message: 'Invalid challenge' })
        assert_equal({ error: { code: 'invalid_challenge', reason: 'invalid', message: 'Invalid challenge' } }, Triauth::Error.process(validation, config))
        assert_equal [[:info, 'Validation error - Invalid challenge (invalid_challenge)', { cause: validation }]], calls

        calls.clear
        other = Triauth::Error.new({ code: 'dns_unavailable', message: 'DNS resolution failed' })
        assert_equal({ error: { code: 'dns_unavailable', message: 'DNS resolution failed' } }, Triauth::Error.process(other, config)) # no `reason` member for an error without a reason
        assert_equal [[:warn, 'DNS resolution failed (dns_unavailable)', { cause: other }]], calls

        calls.clear
        internal = RuntimeError.new('boom')
        assert_equal({ error: { code: 'internal_error', message: 'Internal error' } }, Triauth::Error.process(internal, config))
        assert_equal [[:error, 'Internal error: this is a defect in triauth-ruby - please report it at https://github.com/triauth/triauth-ruby/issues together with the stack trace', { cause: internal }]], calls

        # a config without a logger is tolerated, as `config.logger?.<level>?.(...)` is in JS
        assert_equal({ error: { code: 'internal_error', message: 'Internal error' } }, Triauth::Error.process('not an error', { logger: nil }))
      end
    end
  end
end

TestInternals.logger if __FILE__ == $PROGRAM_NAME
