# frozen_string_literal: true

require_relative '../setup'

# Port-only tests: the regex dialect, the split and one-null rules of `Triauth::Validator` against the probe-6
# characters. This file has no triauth-js counterpart (the validator is covered by the API suites there).
module TestInternals
  def self.validator
    describe 'Triauth.Validator (port-only)' do
      codes = ->(result) { result[:errors].map { |e| [e[:code], e[:reason]] } } # `errors.map((e) => [e.code, e.reason])`
      valid = { valid: true, errors: [] }
      # the JS `\s` set (spelled out as `Helpers::JS_WS`) plus NUL, each one inside the identifier's username / the device name
      js_whitespace_and_nul = {
        'U+00A0' => " ", 'U+FEFF' => "﻿", 'U+2028' => " ", 'U+2029' => " ",
        'VT' => "\v", 'CR' => "\r", 'NUL' => "\0"
      }

      it 'validateIdentifier answers invalid for the JS whitespace set and NUL, not for U+0085; not_lowercase for U+212A (its downcase differs); invalid_username for é' do
        js_whitespace_and_nul.each do |name, ch|
          result = Triauth::Validator.validate_identifier("jo#{ch}hn@triauthdemo.org")
          assert_equal false, result[:valid], name
          assert_equal [{ code: 'invalid_identifier', reason: 'invalid', message: 'Identifier is invalid' }], result[:errors], name
        end
        # U+0085 (NEL) is not JS whitespace: it reaches the username grammar
        assert_equal [%w[invalid_identifier invalid_username]], codes.call(Triauth::Validator.validate_identifier("jo\u0085hn@triauthdemo.org"))
        # U+212A KELVIN SIGN lowercases to `k` under the full Unicode mapping: the identifier is not in lowercase
        assert_equal [%w[invalid_identifier not_lowercase]], codes.call(Triauth::Validator.validate_identifier("joKhn@triauthdemo.org"))
        # `é` is lowercase already, but outside the ASCII username grammar
        assert_equal [%w[invalid_identifier invalid_username]], codes.call(Triauth::Validator.validate_identifier('joéhn@triauthdemo.org'))
        assert_equal valid, Triauth::Validator.validate_identifier('john@triauthdemo.org')
        assert_equal [%w[invalid_identifier invalid_format]], codes.call(Triauth::Validator.validate_identifier('a@b@c.com')) # `scan(/@/).length` counts the signs
        assert_equal [%w[invalid_identifier invalid_username], %w[invalid_identifier invalid_domain]], codes.call(Triauth::Validator.validate_identifier('-a@b'))
        assert_equal [{ code: 'invalid_identifier', reason: 'empty', message: 'Identifier must not be empty' }], Triauth::Validator.validate_identifier('')[:errors]
        assert_equal [%w[invalid_identifier invalid]], codes.call(Triauth::Validator.validate_identifier(5))
      end

      it 'validateDeviceName answers invalid for the JS whitespace set and NUL (plus invalid_characters), invalid_characters only for U+0085 and é, not_lowercase and invalid_characters for U+212A' do
        js_whitespace_and_nul.each do |name, ch|
          assert_equal [%w[invalid_device_name invalid], %w[invalid_device_name invalid_characters]], codes.call(Triauth::Validator.validate_device_name("desk#{ch}top")), name
        end
        assert_equal [%w[invalid_device_name invalid_characters]], codes.call(Triauth::Validator.validate_device_name("desk\u0085top"))
        assert_equal [%w[invalid_device_name not_lowercase], %w[invalid_device_name invalid_characters]], codes.call(Triauth::Validator.validate_device_name("desKtop"))
        assert_equal [%w[invalid_device_name invalid_characters]], codes.call(Triauth::Validator.validate_device_name('désktop'))
        assert_equal valid, Triauth::Validator.validate_device_name('desktop-2')
        # the grammar `\A[a-z0-9]+(-[a-z0-9]+)*\z`: no leading, trailing or consecutive hyphens
        assert_equal [%w[invalid_device_name invalid_characters]], codes.call(Triauth::Validator.validate_device_name('-a'))
        assert_equal [%w[invalid_device_name invalid_characters]], codes.call(Triauth::Validator.validate_device_name('a-'))
        assert_equal [%w[invalid_device_name invalid_characters]], codes.call(Triauth::Validator.validate_device_name('a--b'))
        assert_equal [%w[invalid_device_name empty], %w[invalid_device_name invalid_characters]], codes.call(Triauth::Validator.validate_device_name(''))
        assert_equal [{ code: 'invalid_device_name', reason: 'invalid', message: 'Device name is invalid' }], Triauth::Validator.validate_device_name(nil)[:errors]
      end

      it 'validateSessionKey accepts a bare 43-character key and a lowercase domain prefix, and rejects an uppercase domain, an empty second part, a third part, 42 characters, a non-canonical last character, an empty string, nil and a number (invalid_session_key)' do
        key = '59cKjF500rMz1OrAMqUyLhSbWx1RgJDsWL7dFBDYIP8'
        assert_equal valid, Triauth::Validator.validate_session_key(key)
        assert_equal valid, Triauth::Validator.validate_session_key("example.com:#{key}")
        assert_equal [{ code: 'invalid_session_key', reason: 'invalid', message: 'Invalid session key' }], Triauth::Validator.validate_session_key("Example.com:#{key}")[:errors]
        assert_equal [%w[invalid_session_key invalid]], codes.call(Triauth::Validator.validate_session_key("#{key}:")) # `split(':', -1)` keeps the empty second slot, as JS does: the key is no domain name and the second part is no key
        assert_equal [%w[invalid_session_key invalid]], codes.call(Triauth::Validator.validate_session_key('a:b:c'))
        assert_equal [%w[invalid_session_key invalid]], codes.call(Triauth::Validator.validate_session_key(key[0, 42]))
        assert_equal [%w[invalid_session_key invalid]], codes.call(Triauth::Validator.validate_session_key("#{'A' * 42}B")) # the last character carries data in its unused bits: `base64url_to_uint8` raises
        assert_equal valid, Triauth::Validator.validate_session_key("#{'A' * 42}Q") # the canonical spelling of the same leading bits decodes
        assert_equal [%w[invalid_session_key invalid]], codes.call(Triauth::Validator.validate_session_key('')) # JS `''.split(':')` is `['']`: one empty part, rejected at the length check
        assert_equal [%w[invalid_session_key invalid]], codes.call(Triauth::Validator.validate_session_key(nil))
        assert_equal [%w[invalid_session_key invalid]], codes.call(Triauth::Validator.validate_session_key(123))
      end

      it 'validateAttachments treats an absent sourceUrl as optional under requireSourceUrl = false, rejects a present nil sourceUrl in both modes (the JS null outcome), rejects a duplicated name, and pins the lowercase hex sha256 regex with absolute anchors' do
        sha = 'a' * 64
        url = 'https://example.com/f'
        # `=== undefined` is "member absent" (`key?`): an attachment without the key is optional under require_source_url = false;
        # a present `sourceUrl: nil` member takes the JS null branch (`isCanonicalUrl(null)` is false) and is invalid in both modes
        assert_equal valid, Triauth::Validator.validate_attachments([{ name: 'f', sha256: sha }], false)
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sha256: sha }], true))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sha256: sha }]))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: nil, sha256: sha }], false))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: nil, sha256: sha }], true))
        assert_equal valid, Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: url, sha256: sha }])
        assert_equal valid, Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: url, sha256: sha }, { name: 'g', sourceUrl: url, sha256: sha }])
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: url, sha256: sha }, { name: 'f', sourceUrl: url, sha256: sha }]))
        # `\A[0-9a-f]{64}\z`: lowercase hex only, exactly 64 characters, no trailing newline
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: url, sha256: 'A' * 64 }]))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: url, sha256: "#{sha}\n" }]))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: url, sha256: 'a' * 63 }]))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: url, sha256: 5 }]))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'f', sourceUrl: url, sha256: sha, extra: 1 }]))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ 'name' => 'f', 'sourceUrl' => url, 'sha256' => sha }])) # a String key is an unknown key
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments([{ name: 'n' * 256, sourceUrl: url, sha256: sha }]))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments(nil))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments({}))
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments('x'))
        assert_equal valid, Triauth::Validator.validate_attachments([])
        ten = (0...10).map { |i| { name: "f#{i}", sourceUrl: url, sha256: sha } }
        assert_equal valid, Triauth::Validator.validate_attachments(ten)
        assert_equal [%w[invalid_attachments invalid]], codes.call(Triauth::Validator.validate_attachments(ten + [{ name: 'f10', sourceUrl: url, sha256: sha }]))
      end

      it 'validateExt rejects a non-ASCII key, an Array value and a second nesting level, and accepts one nested level' do
        assert_equal valid, Triauth::Validator.validate_ext({ callbackMethod: 'GET', stampToken: true })
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ 'x-é': 1 })) # `/[^\x20-\x7E]/` on the key
        assert_equal valid, Triauth::Validator.validate_ext({ 'x-a': { b: 1 } })
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ 'x-a': { b: { c: 1 } } }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ 'x-a': [1] }))
        assert_equal valid, Triauth::Validator.validate_ext({})
        assert_equal valid, Triauth::Validator.validate_ext({ a: 1, b: -3, c: false, d: 'é', 'a b': 1 })
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: nil }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ "a\tb": 1 })) # not a normal string
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ __proto__: 1 }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ 'constructor' => 1 })) # the poisoning names are checked by spelling, String keys included
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: { prototype: 1 } }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: 'x' * 4096 })) # `JSON.generate` bytesize above extBytesize
        [nil, false, 0, '', [], 'x', 5, true].each do |ext|
          assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext(ext)), ext.inspect
        end
      end

      it 'validateExt rejects a fraction, a number beyond 2^53 - 1, a non-finite number and an ill-formed string with invalid_ext (port-only)' do
        # `Number.isSafeInteger(e)` (`Helpers.is_safe_integer`): a fraction, a number beyond 2^53 - 1, Infinity and NaN are numbers
        # that `safe_parse_json` would refuse when the ext comes back (`JSON.generate` would raise for the non-finite ones), and the
        # `||` chain rejects them before the sizing; an ill-formed String is the counterpart of a string with an unpaired surrogate,
        # which `isWellFormedString` refuses
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: 1.5 }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: 2**53 }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: 2**60 }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ n: { c: 0.5 } }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: Float::INFINITY }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: -Float::INFINITY }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: Float::NAN }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ n: { c: Float::NAN } }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ a: "x\xED\xA0\x80".dup.force_encoding('UTF-8') }))
        assert_equal [%w[invalid_ext invalid]], codes.call(Triauth::Validator.validate_ext({ n: { a: "\xED\xB0\x80".dup.force_encoding('UTF-8') } }))
        assert_equal valid, Triauth::Validator.validate_ext({ a: 1.0, b: (2**53) - 1, c: 'x', n: { d: -0.0 } }) # an integral Float and the largest safe integer pass
      end

      it 'validateAttestations rejects a provider URL carrying ?, #, %, ; or an apostrophe and accepts the plain https provider' do
        base = 'https://attest.triauthdemo.org/not-a-robot'
        entry = ->(providers) { { label: 'Not a robot', providers: providers } }
        assert_equal valid, Triauth::Validator.validate_attestations({ 'not-a-robot': entry.call([base]) })
        ['?q', '#f', '%41', ';x', "'"].each do |suffix|
          assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ 'not-a-robot': entry.call([base + suffix]) })), suffix
        end
        # two offending providers push invalid twice, as the JS loop does
        assert_equal [%w[invalid_attestations invalid], %w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ a: entry.call(["#{base}?a", "#{base}#b"]) }))
        assert_equal valid, Triauth::Validator.validate_attestations({})
        assert_equal valid, Triauth::Validator.validate_attestations({ a: entry.call(['http://localhost/p']) })
        assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ a: entry.call(['http://example.com/p']) }))
        assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ a: entry.call([]) }))
        assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ a: entry.call([base] * 5) }))
        assert_equal valid, Triauth::Validator.validate_attestations({ a: entry.call([base] * 4) })
        assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ a: { label: 'x', providers: [base], extra: 1 } }))
        assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ a: { providers: [base] } }))
        assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ a: nil })) # `Object.keys(null)` throws in triauth-js
        assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ __proto__: entry.call([base]) }))
        assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations({ "a\tb": entry.call([base]) }))
        five = (1..5).to_h { |i| [:"a#{i}", entry.call([base])] }
        assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations(five))
        assert_equal valid, Triauth::Validator.validate_attestations(five.first(4).to_h)
        [nil, [], 'x', 5].each do |attestations|
          assert_equal [%w[invalid_attestations invalid]], codes.call(Triauth::Validator.validate_attestations(attestations)), attestations.inspect
        end
      end

      it 'validateBinders accepts a bind of recognized binders with string values, rejects an empty, non-string or unknown bind (invalid_signature), and accepts no bind at all' do
        assert_equal valid, Triauth::Validator.validate_binders({ bind: { identifier: 'a' } })
        assert_equal valid, Triauth::Validator.validate_binders({ bind: { identifier: 'a', via: 'https://example.com/', deviceTag: 't' } })
        assert_equal [%w[invalid_signature invalid]], codes.call(Triauth::Validator.validate_binders({ bind: {} }))
        assert_equal [%w[invalid_signature invalid]], codes.call(Triauth::Validator.validate_binders({ bind: { identifier: 1 } }))
        assert_equal [%w[invalid_signature invalid]], codes.call(Triauth::Validator.validate_binders({ bind: { other: 'x' } }))
        assert_equal [%w[invalid_signature invalid]], codes.call(Triauth::Validator.validate_binders({ bind: { identifier: 'a', other: 'x' } }))
        assert_equal [%w[invalid_signature invalid]], codes.call(Triauth::Validator.validate_binders({ bind: { 'identifier' => 'a' } })) # a String key is an unknown binder
        assert_equal [%w[invalid_signature invalid]], codes.call(Triauth::Validator.validate_binders({ bind: nil }))
        assert_equal [%w[invalid_signature invalid]], codes.call(Triauth::Validator.validate_binders({ bind: [] }))
        assert_equal [%w[invalid_signature invalid]], codes.call(Triauth::Validator.validate_binders({ bind: 'identifier' }))
        assert_equal valid, Triauth::Validator.validate_binders({})
        assert_equal valid, Triauth::Validator.validate_binders({ other: 1 })
        assert_equal %i[identifier via deviceTag], Triauth::Validator::BINDER_NAMES
        assert Triauth::Validator::BINDER_NAMES.frozen?
      end

      it 'validateDeviceTag answers invalid, without raising, for the empty string, a lone colon, a trailing colon and a trailing or doubled tilde (the split guards)' do
        tag = '3bi5oE_jXyjGY0WY5n6YqOuzRxfo40fuqDmLGaA5bKQ'
        identifier = 'john@triauthdemo.org'
        invalid = [%w[invalid_device_tag invalid]]
        assert_equal valid, Triauth::Validator.validate_device_tag(tag)
        assert_equal valid, Triauth::Validator.validate_device_tag("#{tag}:#{identifier}:#{tag}")
        # JS `''.split(':')` is `['']` where Ruby gives `[]`: neither is one or three parts; `':'` is two parts on both sides
        assert_equal invalid, codes.call(Triauth::Validator.validate_device_tag(''))
        assert_equal invalid, codes.call(Triauth::Validator.validate_device_tag(':'))
        # a trailing colon keeps its empty third component (`split(':', -1)`), which `is_reported_tag('')` takes without raising
        assert_equal invalid, codes.call(Triauth::Validator.validate_device_tag("#{tag}:#{identifier}:"))
        # a trailing tilde keeps its empty lookup code (`split('~', -1)`), a doubled one a third part
        assert_equal invalid, codes.call(Triauth::Validator.validate_device_tag("#{tag}~"))
        assert_equal invalid, codes.call(Triauth::Validator.validate_device_tag("#{tag}~~"))
      end

      it 'isSafeInteger admits an Integer or an integral Float of magnitude up to 2^53 - 1 and nothing else (the port of Number.isSafeInteger)' do
        [9_007_199_254_740_991, 1.0, 100.0, -0.0, 0].each do |x|
          assert_equal true, Triauth::Helpers.is_safe_integer(x), x.inspect
        end
        [2**53, 1.5, Float::NAN, Float::INFINITY, true, '1', nil].each do |x|
          assert_equal false, Triauth::Helpers.is_safe_integer(x), x.inspect
        end
      end
    end
  end
end

TestInternals.validator if __FILE__ == $PROGRAM_NAME
