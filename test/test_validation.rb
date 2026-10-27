# frozen_string_literal: true

require_relative 'setup'
require 'json'

# The identifiers fixture is read with String keys: the keys of `invalidIdentifiers` are identifier values, not property names.
# (guarded like the zone stub, so that test.rb and a standalone run load it once; shared with test_identity.rb)
IDENTIFIERS_FIXTURE = JSON.parse(File.read(File.expand_path('fixtures/identifiers.json', __dir__))) unless defined?(IDENTIFIERS_FIXTURE)

describe 'Validation API' do
  describe 'Triauth.validate' do
    it 'returns {valid:false, errors} for invalid identifiers' do
      invalid_identifiers = IDENTIFIERS_FIXTURE['invalidIdentifiers']
      results = []
      invalid_identifiers.each_key do |invalid_identifier| # `for...in`; the `errorMsg` read of triauth-js is unused there (`Lint/UselessAssignment` here)
        validation_res = Triauth.validate({ identifier: invalid_identifier })
        results.push(assert_equal(false, validation_res[:valid]))
        results.push(assert(validation_res[:errors].length > 0))
      end
      return results
    end

    it 'returns {valid:true} and no errors for valid identifiers' do
      valid_identifiers = IDENTIFIERS_FIXTURE['validIdentifiers']
      results = []
      valid_identifiers.each do |identifier|
        validation_res = Triauth.validate({ identifier: identifier })
        results.push(assert_equal(true, validation_res[:valid]))
        results.push(assert_equal(0, validation_res[:errors].length))
      end
    end

    it 'returns {valid:false, errors} for invalid device names' do
      invalid_device_names = ['a@a', '', 'Device', 'device_12', 'my device', ' device', 'device ', 'thisdevicenameistoolong', '-pc', 'pc-', 'my--pc', '--pc--', 'xn--pc']
      invalid_device_names.each do |device_name|
        validation_res = Triauth.validate({ deviceName: device_name })
        assert_equal false, validation_res[:valid]
        assert validation_res[:errors].length > 0
      end
    end

    it 'returns {valid:true} and no errors for valid device names' do
      valid_device_names = %w[laptop laptop-12 my-pc-2]
      valid_device_names.each do |device_name|
        validation_res = Triauth.validate({ deviceName: device_name })
        assert_equal true, validation_res[:valid]
        assert_equal 0, validation_res[:errors].length
      end
    end

    it 'rejects an oversized identifier or device name on size alone, before any grammar scan' do
      device_name = Triauth.validate({ deviceName: "#{'a-' * 4_000_000}a" })
      assert_equal([%w[invalid_device_name too_long]], device_name[:errors].map { |e| [e[:code], e[:reason]] })

      identifier = Triauth.validate({ identifier: "#{'a-' * 4_000_000}a@example.com" })
      assert_equal([%w[invalid_identifier too_long]], identifier[:errors].map { |e| [e[:code], e[:reason]] })
    end

    it 'rejects an oversized device tag on length alone, ahead of the split' do
      started = Triauth::Helpers.date_now

      [':' * (8 * 1024 * 1024), '~' * (8 * 1024 * 1024), 'A' * 243].each do |device_tag|
        result = Triauth.validate({ deviceTag: device_tag })
        assert_equal([%w[invalid_device_tag invalid]], result[:errors].map { |e| [e[:code], e[:reason]] })
      end

      # Splitting 16 MiB of delimiters takes hundreds of milliseconds and allocates millions of array entries
      assert Triauth::Helpers.date_now - started < 200, 'an oversized device tag is rejected ahead of any split'
    end

    it 'returns {valid:false, errors:[{code:invalid_arguments}]} for an empty object (nothing to validate)' do
      result = Triauth.validate({})
      assert_equal false, result[:valid]
      assert_equal 1, result[:errors].length
      assert_equal 'invalid_arguments', result[:errors][0][:code]
    end

    it 'returns {valid:false, errors:[{code:invalid_arguments}]} when objects is missing or not a plain object' do
      # `Triauth.validate(undefined)` is the call with no argument here; the other values loop as in triauth-js
      result = Triauth.validate
      assert_equal false, result[:valid]
      assert_equal 1, result[:errors].length
      assert_equal 'invalid_arguments', result[:errors][0][:code]
      [nil, 'john@example.com', 42, true, ['john@example.com']].each do |objects|
        result = Triauth.validate(objects)
        assert_equal false, result[:valid]
        assert_equal 1, result[:errors].length
        assert_equal 'invalid_arguments', result[:errors][0][:code]
      end
    end

    it 'returns {valid:false, errors:[{code:invalid_arguments}]} for misspelled or unrecognized keys' do
      misspelled = [
        { identifer: 'john@example.com' },
        { Identifier: 'john@example.com' },
        { devicename: 'laptop' },
        { identifier: 'john@example.com', extra: true }
      ]
      misspelled.each do |objects|
        result = Triauth.validate(objects)
        assert_equal false, result[:valid]
        assert_equal 1, result[:errors].length
        assert_equal 'invalid_arguments', result[:errors][0][:code]
      end
    end

    # 'returns {valid:false, errors:[{code:invalid_arguments}]} for undefined values' is not ported: Ruby has no `undefined` (a dead branch)

    it 'returns {valid:false, errors} for null and empty values' do
      [{ identifier: nil }, { identifier: '' }, { deviceName: nil }, { deviceName: '' }].each do |objects|
        result = Triauth.validate(objects)
        assert_equal false, result[:valid]
        assert result[:errors].length > 0
        assert result[:errors].all? { |e| !e[:reason].nil? }, 'null/empty values should fail with field validation errors'
      end
    end

    it 'returns {valid:true} when both identifier and deviceName are valid' do
      result = Triauth.validate({ identifier: 'john@example.com', deviceName: 'laptop' })
      assert_equal true, result[:valid]
      assert_equal 0, result[:errors].length
    end

    it 'accumulates errors from both identifier and deviceName when both are invalid' do
      result = Triauth.validate({ identifier: 'bad-no-at-sign', deviceName: 'BAD DEVICE' })
      assert_equal false, result[:valid]
      assert result[:errors].length >= 2, 'should have at least one error per invalid field'
    end

    it 'returns {valid:false} with only deviceName errors when identifier is valid' do
      result = Triauth.validate({ identifier: 'john@example.com', deviceName: 'BAD DEVICE' })
      assert_equal false, result[:valid]
      assert result[:errors].length > 0
      assert result[:errors].all? { |e| e[:code] == 'invalid_device_name' }, 'errors should be deviceName errors only'
    end
  end
end
