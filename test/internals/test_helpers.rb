# frozen_string_literal: true

require_relative '../setup'
require 'socket'

module TestInternals
  def self.helpers
    describe 'Triauth.Helpers' do
      describe 'safeParseJson' do
        it 'limits the bytesize of a string to parse' do
          limit = Triauth::LIMITS[:jsonMaxBytesize]

          json_string = "{\"a\":\"#{'A' * (limit - 8)}\"}"
          json_result = Triauth::Helpers.safe_parse_json(json_string)
          assert_kind_of Hash, json_result

          assert_raises(StandardError) do
            json_string = "{\"a\":\"#{'A' * (limit - 7)}\"}"
            Triauth::Helpers.safe_parse_json(json_string)
          end
        end

        it 'only allows objects to be encoded (no arrays)' do
          json_result = Triauth::Helpers.safe_parse_json('{}')
          assert_kind_of Hash, json_result

          ['[]', '"string"', '11', '3.14', 'true', 'false', 'null'].each do |str|
            assert_raises(StandardError) do
              Triauth::Helpers.safe_parse_json(str)
            end
          end
        end

        it 'rejects the prototype-poisoning member names, whatever their value' do
          ['{"__proto__": {"isAdmin": true}}', '{"constructor": {"prototype": {"isAdmin": true}}}', '{"a":{"constructor": {"prototype": {"isAdmin": true}}}}', '{"constructor": 5}', '{"prototype": {}}', '{"a":[{"constructor": null}]}'].each do |str|
            assert_raises(StandardError) do
              Triauth::Helpers.safe_parse_json(str)
            end
          end
        end

        it 'only allows ASCII non-control keys with limited length' do
          limit = Triauth::LIMITS[:jsonMaxKeyLength]
          ['{"Ą":"A"}', "{\"lorem\nipsum\":\"dolor sit\"}", "{\"#{'A' * (limit + 1)}\":\"A\"}"].each do |str|
            assert_raises(StandardError) do
              Triauth::Helpers.safe_parse_json(str)
            end
          end
        end

        it 'rejects string values with an unpaired surrogate escape, in any position' do
          # A lone surrogate has no UTF-8 encoding. Its \uXXXX escape is the one spelling of an ill-formed
          # string that passes the strict UTF-8 decoder, because the JSON text itself is plain ASCII.
          ['{"a":"\\ud800"}', '{"a":"x\\udfffy"}', '{"a":"\\udc00\\ud800"}', '{"a":{"b":"\\ud800"}}', '{"a":["ok","\\ud800"]}'].each do |str|
            assert_raises(StandardError, str) do
              Triauth::Helpers.safe_parse_json(str)
            end
          end

          # A high-then-low escape pair is one code point and is accepted
          assert_equal "\u{1F389}", Triauth::Helpers.safe_parse_json('{"a":"\\ud83c\\udf89"}')[:a]
        end

        it 'accepts only whole numbers of magnitude up to 2^53 - 1' do
          # Every JSON parser reads these numbers to the same value: each one is an exact IEEE double,
          # and a parser that keeps integers exact reads the same integer
          [['{"n":9007199254740991}', 9_007_199_254_740_991], ['{"n":-9007199254740991}', -9_007_199_254_740_991], ['{"n":0}', 0], ['{"n":1.0}', 1], ['{"n":1e2}', 100], ['{"n":[{"m":-7}]}', [{ m: -7 }]]].each do |str, value|
            assert_equal value, Triauth::Helpers.safe_parse_json(str)[:n], str
          end

          ['{"n":9007199254740992}', '{"n":-9007199254740992}', '{"n":9007199254740993}', '{"n":1.5}', '{"n":1e-7}', '{"n":1e400}', '{"n":-1e400}', '{"a":{"n":0.5}}', '{"a":[1,2.5]}'].each do |str|
            assert_raises(StandardError, str) do
              Triauth::Helpers.safe_parse_json(str)
            end
          end
        end

        it 'limits the nesting level' do
          limit = Triauth::LIMITS[:jsonMaxNestingDepth]
          obj = {}
          root = obj

          # Build a chain whose total nesting depth equals the limit (root counts as depth 1, so we
          # add limit-1 children below root). This is the maximum allowed depth and should be accepted.
          (limit - 1).times do |i|
            obj[i] = {}
            obj = obj[i]
          end

          json_result = Triauth::Helpers.safe_parse_json(JSON.generate(root))
          assert_kind_of Hash, json_result

          # A null at the deepest level adds no level: only objects and arrays count.
          obj['n'] = nil
          json_result = Triauth::Helpers.safe_parse_json(JSON.generate(root))
          assert_kind_of Hash, json_result

          # Adding one more nested object pushes the depth past the limit — should be rejected.
          obj['z'] = {}

          assert_raises(StandardError) do
            Triauth::Helpers.safe_parse_json(JSON.generate(root))
          end
        end

        it 'accepts wide objects and arrays as member counts are bounded by the bytesize cap' do
          json_vals = []
          2000.times do |i|
            json_vals.push("\"#{i}\":\"A\"")
          end

          wide_object = Triauth::Helpers.safe_parse_json("{#{json_vals.join(',')}}")
          assert_equal 2000, wide_object.keys.length

          wide_array = Triauth::Helpers.safe_parse_json("{\"list\":[#{Array.new(2000) { |i| i }.join(',')}]}")
          assert_equal 2000, wide_array[:list].length
        end
      end

      describe 'stringToBase64Url / base64UrlToString' do
        it 'round-trips strings from any script (UTF-8)' do
          samples = [
            '{"a":1}',
            'café',
            'Привет мир',
            '日本語のテスト',
            'zażółć gęślą jaźń',
            "ok \u{1F389}",
            "mixed: é Привет 日本語 \u{1F680}\u{1F389}"
          ]

          samples.each do |s|
            assert_equal s, Triauth::Helpers.base64url_to_string(Triauth::Helpers.string_to_base64url(s)), s
          end
        end

        it 'encodes the UTF-8 bytes of the string (exact encodings)' do
          # ASCII payloads must stay bit-identical to the historical encoding — recorded
          # challenges/signatures in test/fixtures/json/*.json depend on this.
          assert_equal 'eyJhIjoxfQ', Triauth::Helpers.string_to_base64url('{"a":1}')

          # 'é' must encode as its UTF-8 bytes C3 A9, not the latin-1 byte E9 ('6Q') that the
          # old btoa()-based implementation produced.
          assert_equal 'w6k', Triauth::Helpers.string_to_base64url('é')
          assert_equal 'é', Triauth::Helpers.base64url_to_string('w6k')
        end

        it 'throws on byte sequences that are not well-formed UTF-8' do
          # '6Q' is the latin-1 (pre-UTF-8) encoding of 'é' — the lone byte E9 is ill-formed
          # UTF-8. Rejecting (never substituting U+FFFD) keeps exactly one byte spelling per
          # string; callers map the TypeError to invalid_challenge (challenge) / invalid_signature (metadata) on the wire.
          assert_raises(TypeError) do
            Triauth::Helpers.base64url_to_string('6Q')
          end
        end

        it 'does not strip a UTF-8 BOM, so a BOM-prefixed JSON payload stays rejected' do
          # '77u_eyJhIjoxfQ' is EF BB BF + '{"a":1}'. The BOM bytes are well-formed UTF-8, so
          # the decoder returns them as U+FEFF — byte-visible, never sniffed away. A decoder
          # that stripped it would accept a second, non-canonical byte encoding of the same
          # JSON past safeParseJson.
          decoded = Triauth::Helpers.base64url_to_string('77u_eyJhIjoxfQ')
          assert_equal "﻿{\"a\":1}", decoded

          assert_raises(StandardError) do
            Triauth::Helpers.safe_parse_json(decoded)
          end
        end

        it 'still throws on malformed base64url input' do
          assert_raises(StandardError) do
            Triauth::Helpers.base64url_to_string('A') # length ≡ 1 (mod 4) is never valid base64
          end
        end

        it 'throws on unpaired surrogates when encoding' do
          # Ill-formed UTF-16 has no UTF-8 encoding. Unreachable from the public API (both call
          # sites encode JSON.stringify output, which escapes unpaired surrogates as \udXXX).
          # The Ruby counterpart of a lone surrogate is an ill-formed UTF-8 string.
          assert_raises(TypeError) do
            Triauth::Helpers.string_to_base64url("\xED\xA0\x80".dup.force_encoding('UTF-8'))
          end
        end
      end

      describe 'stringToUtf8Bytes / utf8BytesToString / byteSize' do
        # the `decodeThrows` lambda of triauth-js is an instance method here, as it uses the assertions
        define_method(:decode_throws) do |bytes, label|
          assert_raises(TypeError, label) do
            Triauth::Helpers.utf8_bytes_to_string(bytes.pack('C*'))
          end
        end

        it 'rejects every class of ill-formed UTF-8 sequence' do
          # Overlong encodings — a shorter spelling of the same code point exists
          decode_throws([0xC0, 0x80], 'overlong NUL (C0 80)')
          decode_throws([0xC1, 0xBF], 'overlong (C1 BF)')
          decode_throws([0xE0, 0x80, 0xAF], 'overlong (E0 80 AF)')
          decode_throws([0xF0, 0x80, 0x80, 0x8F], 'overlong (F0 80 80 8F)')

          # The UTF-16 surrogate range U+D800-U+DFFF has no UTF-8 encoding
          decode_throws([0xED, 0xA0, 0x80], 'encoded surrogate U+D800 (ED A0 80)')
          decode_throws([0xED, 0xBF, 0xBF], 'encoded surrogate U+DFFF (ED BF BF)')

          # Above U+10FFFF
          decode_throws([0xF4, 0x90, 0x80, 0x80], 'U+110000 (F4 90 80 80)')
          decode_throws([0xF5, 0x80, 0x80, 0x80], 'lead byte F5')
          decode_throws([0xFF], 'lead byte FF')

          # Truncated and stray sequences
          decode_throws([0xE9], 'lone latin-1 high byte (E9)')
          decode_throws([0xC3], 'truncated 2-byte sequence')
          decode_throws([0xE2, 0x82], 'truncated 3-byte sequence')
          decode_throws([0xF0, 0x9F, 0x92], 'truncated 4-byte sequence')
          decode_throws([0x80], 'stray continuation byte')
          decode_throws([0xC3, 0x28], 'lead followed by a non-continuation byte')
        end

        it 'decodes the full well-formed range, boundaries included' do
          cases = [
            [[], ''],
            [[0x00], "\u0000"],
            [[0x0A, 0x7F], "\n\u007F"],
            [[0xC2, 0x80], "\u0080"],
            [[0xDF, 0xBF], "߿"],
            [[0xE0, 0xA0, 0x80], "ࠀ"],
            [[0xED, 0x9F, 0xBF], "퟿"],           # last code point below the surrogate gap
            [[0xEE, 0x80, 0x80], ""],           # first code point above it
            [[0xEF, 0xBF, 0xBD], "�"],           # a literal replacement character is well-formed
            [[0xEF, 0xBB, 0xBF, 0x61], "﻿a"],    # BOM kept byte-visible, not stripped
            [[0xF0, 0x90, 0x80, 0x80], "\u{10000}"],
            [[0xF4, 0x8F, 0xBF, 0xBF], "\u{10FFFF}"]
          ]

          cases.each do |bytes, expected|
            assert_equal expected, Triauth::Helpers.utf8_bytes_to_string(bytes.pack('C*')), bytes.join(',')
          end
        end

        it 'encodes each UTF-8 length class byte-exactly and round-trips' do
          cases = [
            ['', []],
            ['A', [0x41]],
            ['é', [0xC3, 0xA9]],
            ['€', [0xE2, 0x82, 0xAC]],
            ["\u{1F389}", [0xF0, 0x9F, 0x8E, 0x89]]
          ]

          cases.each do |s, bytes|
            assert_equal bytes, Triauth::Helpers.string_to_utf8_bytes(s).bytes, s.inspect
            assert_equal s, Triauth::Helpers.utf8_bytes_to_string(Triauth::Helpers.string_to_utf8_bytes(s))
          end
        end

        it 'rejects unpaired surrogates when encoding' do
          # ill-formed UTF-8 strings (encoded surrogates), the Ruby counterpart of the lone surrogates
          ["\xED\xA0\x80", "\xED\xB0\x80", "a\xED\xA0\x80z", "\xED\xA0\x80\xED\xA0\x80", "tail\xED\xAF\xBF"].each do |s|
            assert_raises(TypeError, s.inspect) do
              Triauth::Helpers.string_to_utf8_bytes(s.dup.force_encoding('UTF-8'))
            end
          end
        end

        it 'byteSize counts UTF-8 bytes without ever throwing' do
          assert_equal 0, Triauth::Helpers.byte_size('')
          assert_equal 3, Triauth::Helpers.byte_size('abc')
          assert_equal 2, Triauth::Helpers.byte_size('é')
          assert_equal 3, Triauth::Helpers.byte_size('€')
          assert_equal 4, Triauth::Helpers.byte_size("\u{1F389}")
          assert_equal 4, Triauth::Helpers.byte_size('𐀀') # a valid pair is one 4-byte code point

          # An unpaired surrogate counts as 3 bytes (the length of its U+FFFD substitute), so
          # limit checks stay meaningful even for strings the strict codec refuses to encode.
          # Here: the raw bytes of an ill-formed string are counted.
          assert_equal 3, Triauth::Helpers.byte_size("\xED\xA0\x80".dup.force_encoding('UTF-8'))
          assert_equal 5, Triauth::Helpers.byte_size("a\xED\xB0\x80b".dup.force_encoding('UTF-8'))
        end

        it 'agrees with the platform codecs across a randomized corpus (differential oracle)' do
          # The oracle is Ruby's own codec: `Array#pack('U*')` encodes, `force_encoding` + `valid_encoding?` decodes strictly.

          # Deterministic Park-Miller LCG so any failure reproduces exactly
          state = 0xC0FFEE
          rand = lambda do |n|
            state = (state * 48_271) % 2_147_483_647
            state % n
          end

          random_well_formed = lambda do
            s = +''
            len = rand.call(64)
            len.times do
              bucket = rand.call(4)
              cp = nil
              case bucket
              when 0
                cp = rand.call(0x80)                                            # ASCII
              when 1
                cp = 0x80 + rand.call(0x800 - 0x80)                             # 2-byte
              when 2
                # 3-byte
                loop do
                  cp = 0x800 + rand.call(0x10000 - 0x800)
                  break unless cp.between?(0xD800, 0xDFFF)
                end
              else
                cp = 0x10000 + rand.call(0x110000 - 0x10000)                    # astral (4-byte)
              end
              s << cp.chr(Encoding::UTF_8)
            end
            s
          end

          300.times do
            s = random_well_formed.call
            encoded = Triauth::Helpers.string_to_utf8_bytes(s)

            assert_equal s.codepoints.pack('U*').bytes, encoded.bytes, s.inspect
            assert_equal encoded.dup.force_encoding(Encoding::UTF_8), Triauth::Helpers.utf8_bytes_to_string(encoded), s.inspect
            assert_equal encoded.bytesize, Triauth::Helpers.byte_size(s), s.inspect

            # Mutate one byte: both codecs must agree — same decoded string, or both reject
            if encoded.bytesize > 0
              mutated = encoded.dup
              mutated.setbyte(rand.call(mutated.bytesize), rand.call(256))

              ours = nil
              oracle = nil
              begin
                ours = Triauth::Helpers.utf8_bytes_to_string(mutated)
              rescue TypeError
                # rejection recorded as nil
              end
              candidate = mutated.dup.force_encoding(Encoding::UTF_8)
              oracle = candidate if candidate.valid_encoding?

              if oracle.nil?
                assert_nil ours, "bytes: #{mutated.bytes.join(',')}"
              else
                assert_equal oracle, ours, "bytes: #{mutated.bytes.join(',')}"
              end
            end
          end
        end
      end

      describe 'isWellFormedString' do
        it 'accepts every string without an unpaired surrogate, and no non-string' do
          ['', 'plain', 'Привет', "\u{1F389}", "\u{D7FF}\u{FFFD}", '🎉'].each do |s|
            assert_equal true, Triauth::Helpers.is_well_formed_string(s), s.inspect
          end
          # `undefined` and `null` are both nil here; `{toString: () => 'a'}` is an object answering `to_s`
          to_s_object = Object.new
          to_s_object.define_singleton_method(:to_s) { 'a' }
          [nil, 1, true, ['a'], to_s_object].each do |v|
            assert_equal false, Triauth::Helpers.is_well_formed_string(v), v.to_s
          end
        end

        it 'rejects a lone, leading, trailing or mis-paired surrogate' do
          # the JS strings hold surrogate code points, which no Ruby String can spell: the UTF-8-tagged byte strings those
          # code points would occupy (ill-formed Strings) stand in for them
          ["\xED\xA0\x80", "\xED\xA0\x80x", "x\xED\xBF\xBF", "\xED\xB0\x80\xED\xA0\x80", "🎉\xED\xA0\xBC"].each do |s|
            assert_equal false, Triauth::Helpers.is_well_formed_string(s.dup.force_encoding('UTF-8')), s.inspect
          end
        end
      end

      describe 'Triauth.Helpers.verifyOptionsSchema' do
        schema = { use: [/\A(auth|sign)\z/], mode: %w[public private] }

        it 'accepts whitelisted critical options by exact string or regexp match' do
          assert_equal true, Triauth::Helpers.verify_options_schema({}, schema)
          assert_equal true, Triauth::Helpers.verify_options_schema({ use: 'auth', mode: 'private' }, schema)
        end

        it 'rejects unknown critical options and non-matching values' do
          assert_equal false, Triauth::Helpers.verify_options_schema({ unknown: '1' }, schema)
          assert_equal false, Triauth::Helpers.verify_options_schema({ use: 'bogus' }, schema)
          assert_equal false, Triauth::Helpers.verify_options_schema({ mode: '' }, schema)
          assert_equal false, Triauth::Helpers.verify_options_schema({ use: 42 }, schema)
        end

        it 'passes x- experimental options as long as they are normal strings' do
          assert_equal true, Triauth::Helpers.verify_options_schema({ 'x-lab': 'on' }, schema)
          assert_equal false, Triauth::Helpers.verify_options_schema({ 'x-lab': "a\x00b" }, schema)
        end

        it 'accepts predicate values on an exactly-true return, rejecting anything else' do
          predicated = { list: [->(v) { v.split(',', -1).all? { |entry| entry.length > 0 } }] }
          assert_equal true, Triauth::Helpers.verify_options_schema({ list: 'a,b' }, predicated)
          assert_equal false, Triauth::Helpers.verify_options_schema({ list: 'a,' }, predicated)

          # A truthy-but-not-true return does not accept
          assert_equal false, Triauth::Helpers.verify_options_schema({ list: 'x' }, { list: [->(_v) { 1 }] })

          # Non-string values never reach the predicate (this one would throw on 42)
          assert_equal false, Triauth::Helpers.verify_options_schema({ list: 42 }, { list: [->(v) { v.start_with?('a') }] })
        end

        it 'matches each option against its full allowed-value list: strings, regexps, and predicates compose' do
          mixed = { v: ['literal', /\Aregexp\z/, ->(x) { x == 'predicate' }] }
          assert_equal true, Triauth::Helpers.verify_options_schema({ v: 'literal' }, mixed)
          assert_equal true, Triauth::Helpers.verify_options_schema({ v: 'regexp' }, mixed)
          assert_equal true, Triauth::Helpers.verify_options_schema({ v: 'predicate' }, mixed)
          assert_equal false, Triauth::Helpers.verify_options_schema({ v: 'other' }, mixed)
        end
      end

      describe 'randomString' do
        it 'draws bytes from the passed config.randomSource, defaulting to the global config' do
          # A per-call effective config with a deterministic byte stream must shape the output
          zeroes = ->(n) { "\x00".b * n }
          assert_equal 'A' * 24, Triauth::Helpers.random_string(24, { randomSource: zeroes })

          # Without the argument, the global Triauth.config.randomSource applies
          saved = Triauth.config[:randomSource]
          begin
            Triauth.config[:randomSource] = ->(n) { "\xff".b * n }
            assert_equal '____', Triauth::Helpers.random_string(4)
          ensure
            Triauth.config[:randomSource] = saved
          end
        end

        it 'threads a per-call config.randomSource into the challenge nonce (Challenge.build)' do
          identity = Triauth::Identity.new('john@triauthdemo.org')
          challenge = Triauth::Challenge.build('auth', identity, {}, { randomSource: ->(n) { "\x00".b * n } })

          assert_equal 'A' * 24, challenge.data[:nonce]
        end
      end

      describe 'decodeP256PublicKey' do
        # The P-256 generator point G, its negation -G (the same x, y replaced by p - y), and the field prime p
        # (`GX`, `GY`, `NEG_GY`, `P`, `X5`, `X5_PLUS_P` are locals here: a constant cannot be assigned inside a method body)
        gx = '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
        gy = '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'     # odd
        neg_gy = 'b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a' # even
        p = 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'
        x5 = '0000000000000000000000000000000000000000000000000000000000000005'   # x = 5 has a point on the curve
        x5_plus_p = 'ffffffff00000001000000000000000000000001000000000000000000000004'
        # the `INVALID` matcher `{name: 'TypeError', message: 'Invalid public key'}` is the `assert_raises(TypeError)` and the message check of each `it`

        bytes = ->(hex) { [hex].pack('H*') }
        decode = ->(hex) { Triauth::Helpers.decode_p256_public_key(bytes.call(hex)) }

        it 'returns an uncompressed point (65 bytes, prefix 0x04) unchanged' do
          point = bytes.call("04#{gx}#{gy}")
          assert_same point, Triauth::Helpers.decode_p256_public_key(point)
        end

        it 'decodes a compressed point: prefix 0x03 gives the odd y, prefix 0x02 the even y' do
          assert_equal bytes.call("04#{gx}#{gy}"), decode.call("03#{gx}")
          assert_equal bytes.call("04#{gx}#{neg_gy}"), decode.call("02#{gx}")
        end

        it 'decodes the compressed form of generated keys of both prefixes to the point that Web Crypto exports' do
          prefixes = Set.new
          i = 0
          while prefixes.size < 2 && i < 64
            key_pair = OpenSSL::PKey::EC.generate('prime256v1')
            raw = key_pair.public_key.to_octet_string(:uncompressed)
            compressed = [0x02 | (raw.getbyte(64) & 1)].pack('C') + raw.byteslice(1, 32)

            assert_equal raw, Triauth::Helpers.decode_p256_public_key(compressed)
            prefixes.add(compressed.getbyte(0))
            i += 1
          end
          assert_equal 2, prefixes.size
        end

        it 'rejects an x of p or more, so that a key has one compressed form only' do
          assert_equal 65, decode.call("02#{x5}").bytesize
          err = assert_raises(TypeError) { decode.call("02#{x5_plus_p}") }
          assert_equal 'Invalid public key', err.message
          err = assert_raises(TypeError) { decode.call("02#{p}") }
          assert_equal 'Invalid public key', err.message
        end

        it 'rejects an x that has no point on the curve' do
          err = assert_raises(TypeError) { decode.call('0201a3be660e801c951552e2fcda9c4f6c6abcdfe64d7ca84b1cf5a47cc2e1f357') }
          assert_equal 'Invalid public key', err.message
        end

        it 'rejects the hybrid form (prefix 0x06 or 0x07), also with the parity bit that matches y' do
          err = assert_raises(TypeError) { decode.call("07#{gx}#{gy}") }
          assert_equal 'Invalid public key', err.message
          err = assert_raises(TypeError) { decode.call("06#{gx}#{gy}") }
          assert_equal 'Invalid public key', err.message
          err = assert_raises(TypeError) { decode.call("06#{gx}#{neg_gy}") }
          assert_equal 'Invalid public key', err.message
        end

        it 'rejects every other prefix and length' do
          [
            '',                    # empty
            '00',                  # the point at infinity
            "05#{gx}",             # no SEC 1 form, although its low bit is the parity of y
            "04#{gx}",             # the uncompressed prefix on 33 bytes
            "03#{gx}#{gy}",        # a compressed prefix on 65 bytes
            "03#{gx[2..]}",        # 32 bytes
            "03#{gx}00",           # 34 bytes
            "04#{gx}#{gy}00"       # 66 bytes
          ].each do |hex|
            err = assert_raises(TypeError, hex) { decode.call(hex) }
            assert_equal 'Invalid public key', err.message, hex
          end
        end
      end

      # The tests below exist only in the port: they pin the Ruby
      # semantics of the regex dialect, the number model and the strict decoders, which no triauth-js test can cover.

      # the probe-6 edge characters
      edge = {
        nbsp: " ", nel: "\u0085", bom: "﻿", ls: " ", ps: " ", cr: "\r", vt: "\v",
        kelvin: "K", eacute: 'é', arabic_three: "٣", emoji: "\u{1F600}"
      }

      describe 'regex dialect (port-only)' do
        it 'isNormalString admits letters and numbers of every script and no whitespace but the space' do
          assert_equal true, Triauth::Helpers.is_normal_string('a b')
          assert_equal true, Triauth::Helpers.is_normal_string(edge[:eacute])
          assert_equal true, Triauth::Helpers.is_normal_string(edge[:kelvin]) # KELVIN SIGN is a letter (Lu) in JS `\p{L}` as well
          assert_equal true, Triauth::Helpers.is_normal_string(edge[:arabic_three])
          %i[nbsp nel bom ls ps cr vt emoji].each do |name|
            assert_equal false, Triauth::Helpers.is_normal_string("a#{edge[name]}b"), name.to_s
          end
          assert_equal false, Triauth::Helpers.is_normal_string("a\tb")
          assert_equal false, Triauth::Helpers.is_normal_string("a\nb")
          assert_equal false, Triauth::Helpers.is_normal_string("a\u0000b")

          # the whole punctuation set of the JS class, and nothing outside it
          assert_equal true, Triauth::Helpers.is_normal_string("~!@#$%^&*()_-+={}[]|\\:;\"'<,>.?/")
          assert_equal false, Triauth::Helpers.is_normal_string('a`b')

          # nil and 0 leave the bytesize unbound (the JS `if (bytesizeLimit && ...)`)
          assert_equal false, Triauth::Helpers.is_normal_string('a' * 256)
          assert_equal true, Triauth::Helpers.is_normal_string('a' * 256, nil)
          assert_equal true, Triauth::Helpers.is_normal_string('a' * 256, 0)
          assert_equal false, Triauth::Helpers.is_normal_string('ab', 1)
        end

        it 'isDomainName, hasPunycodeLabel and isLookupCode use expanded ASCII classes, never the i flag' do
          assert_equal true, Triauth::Helpers.is_domain_name('EXAMPLE.COM')
          assert_equal true, Triauth::Helpers.is_domain_name('Kexample.com')
          assert_equal false, Triauth::Helpers.is_domain_name("#{edge[:kelvin]}example.com") # Ruby's `/[a-z]/i` would admit U+212A
          assert_equal false, Triauth::Helpers.is_domain_name("example.#{edge[:eacute]}")
          assert_equal false, Triauth::Helpers.is_domain_name("example.com#{edge[:nbsp]}")
          assert_equal false, Triauth::Helpers.is_domain_name("example.com\n")
          assert_equal false, Triauth::Helpers.is_domain_name('a.0X7F')
          assert_equal false, Triauth::Helpers.is_domain_name('a.XN--p1ai')

          assert_equal true, Triauth::Helpers.has_punycode_label('XN--abc.com')
          assert_equal true, Triauth::Helpers.has_punycode_label('a.xN--abc')
          assert_equal false, Triauth::Helpers.has_punycode_label("#{edge[:kelvin]}n--abc.com")
          assert_equal false, Triauth::Helpers.has_punycode_label("a\nxn--abc.com")

          assert_equal true, Triauth::Helpers.is_lookup_code('ABCDEFGHIJKLMNOP')
          assert_equal false, Triauth::Helpers.is_lookup_code('abcdefghijklmnop')
          assert_equal false, Triauth::Helpers.is_lookup_code("ABCDEFGHIJKLMNO#{edge[:kelvin]}")
          assert_equal false, Triauth::Helpers.is_lookup_code("ABCDEFGHIJKLMNOP\n")
          assert_equal false, Triauth::Helpers.is_lookup_code('ABCDEFGHIJKLMNOPQ')
        end

        it 'trim and trimEnd strip exactly the JS whitespace set: NUL and U+0085 are kept, U+FEFF and U+00A0 stripped' do
          stripped = "\t\n\v\f\r #{edge[:nbsp]}#{edge[:bom]}#{edge[:ls]}#{edge[:ps]}     　"
          assert_equal 'a', Triauth::Helpers.trim("#{stripped}a#{stripped}")
          assert_equal "#{stripped}a", Triauth::Helpers.trim_end("#{stripped}a#{stripped}")
          assert_equal "a \u0000", Triauth::Helpers.trim("a \u0000 ")
          assert_equal "#{edge[:nel]}a#{edge[:nel]}", Triauth::Helpers.trim(" #{edge[:nel]}a#{edge[:nel]} ")
          assert_equal "a#{edge[:nel]}", Triauth::Helpers.trim_end("a#{edge[:nel]} ")
          assert_equal '', Triauth::Helpers.trim(stripped)
          assert_equal 'a b', Triauth::Helpers.trim_end('a b')
        end
      end

      describe 'type predicates (port-only)' do
        it 'isString admits well-formed UTF-8 and ASCII-only Strings only' do
          assert_equal true, Triauth::Helpers.is_string('')
          assert_equal true, Triauth::Helpers.is_string("é #{edge[:emoji]}")
          assert_equal false, Triauth::Helpers.is_string("\xED\xA0\x80".dup.force_encoding('UTF-8'))
          assert_equal false, Triauth::Helpers.is_string("a\xE9b".dup.force_encoding('UTF-8'))
          assert_equal true, Triauth::Helpers.is_string('abc'.b)
          assert_equal true, Triauth::Helpers.is_string('abc'.encode('US-ASCII'))
          assert_equal false, Triauth::Helpers.is_string("\xC3\xA9".b)
          assert_equal false, Triauth::Helpers.is_string('abc'.encode('UTF-16LE'))
          assert_equal false, Triauth::Helpers.is_string('é'.encode('ISO-8859-1'))
          [nil, 1, 1.5, true, false, :abc, [], {}, Object.new].each do |value|
            assert_equal false, Triauth::Helpers.is_string(value), value.inspect
          end
        end

        it 'isNumber and isInteger follow the JS number model' do
          assert_equal true, Triauth::Helpers.is_number(1)
          assert_equal true, Triauth::Helpers.is_number(1.5)
          assert_equal true, Triauth::Helpers.is_number(Float::NAN)
          assert_equal true, Triauth::Helpers.is_number(Float::INFINITY)
          assert_equal true, Triauth::Helpers.is_number(2**64)
          [true, false, nil, '1', :one, [], {}, Rational(1, 2)].each do |value|
            assert_equal false, Triauth::Helpers.is_number(value), value.inspect
          end

          assert_equal true, Triauth::Helpers.is_integer(30)
          assert_equal true, Triauth::Helpers.is_integer(30.0)
          assert_equal true, Triauth::Helpers.is_integer(-0.0)
          assert_equal true, Triauth::Helpers.is_integer(2**64)
          assert_equal false, Triauth::Helpers.is_integer(1.5)
          assert_equal false, Triauth::Helpers.is_integer(Float::NAN)
          assert_equal false, Triauth::Helpers.is_integer(Float::INFINITY)
          assert_equal false, Triauth::Helpers.is_integer(-Float::INFINITY)
          [true, false, nil, '1', :one, [], {}].each do |value|
            assert_equal false, Triauth::Helpers.is_integer(value), value.inspect
          end
        end
      end

      describe 'safeParseJson number model (port-only)' do
        it 'turns integral Floats of safe-integer magnitude into Integers, in objects and arrays alike, and rejects every other number' do
          result = Triauth::Helpers.safe_parse_json('{"a":30.0,"c":[2.0],"d":-0.0,"e":9007199254740991.0,"f":1E2}')
          assert_equal({ a: 30, c: [2], d: 0, e: 9_007_199_254_740_991, f: 100 }, result)
          assert_kind_of Integer, result[:a]
          assert_kind_of Integer, result[:c][0]
          assert_kind_of Integer, result[:d]
          assert_kind_of Integer, result[:e]
          assert_kind_of Integer, result[:f]
          # a fraction, 2**53 itself (a Float or an exact Integer), a larger exact Integer (which JS would round) and Infinity are
          # rejected by the walk's safe-integer rule, in an Array as in a Hash
          ['{"a":1.5}', '{"a":9007199254740992.0}', '{"a":9007199254740992}', '{"a":9007199254740993}', '{"a":1e400}', '{"a":[1.5]}'].each do |str|
            assert_raises(RuntimeError, str) { Triauth::Helpers.safe_parse_json(str) }
          end
        end

        it 'raises a StandardError for a parser failure and for a parser nesting overflow, like the JS SyntaxError' do
          assert_operator JSON::ParserError, :<, StandardError
          assert_operator JSON::NestingError, :<, StandardError
          assert_raises(JSON::ParserError) do
            Triauth::Helpers.safe_parse_json('{')
          end
          assert_raises(JSON::NestingError) do
            Triauth::Helpers.safe_parse_json("{\"a\":#{'[' * 101}#{']' * 101}}")
          end
          # `1e400` parses to Infinity here as it does in JS (never a parser failure), and the walk's safe-integer rule rejects it
          assert_raises(RuntimeError) do
            Triauth::Helpers.safe_parse_json('{"a":1e400}')
          end
        end

        it 'counts only Hashes and Arrays as nesting levels: a scalar at the limit adds none, an empty Array or Hash one' do
          limit = Triauth::LIMITS[:jsonMaxNestingDepth]
          at_limit = "#{'{"a":' * (limit - 1)}{\"a\":1}#{'}' * (limit - 1)}"
          assert_kind_of Hash, Triauth::Helpers.safe_parse_json(at_limit)
          ['null', 'true', 'false', '"x"', '-7'].each do |scalar|
            assert_kind_of Hash, Triauth::Helpers.safe_parse_json("#{'{"a":' * (limit - 1)}{\"a\":#{scalar}}#{'}' * (limit - 1)}"), scalar
          end
          ['[]', '{}', '[1]', '[[]]'].each do |container|
            assert_raises(RuntimeError, container) do
              Triauth::Helpers.safe_parse_json("#{'{"a":' * (limit - 1)}{\"a\":#{container}}#{'}' * (limit - 1)}")
            end
          end
          assert_equal({ a: nil, b: [nil, 1], c: { d: nil } }, Triauth::Helpers.safe_parse_json('{"a":null,"b":[null,1],"c":{"d":null}}'))
        end
      end

      describe 'safeParseJson grammar (port-only)' do
        it 'rejects what the json gem admits beyond JSON.parse of JS: comments and unknown escapes' do
          # accepted by JSON.parse in JS and here: `/` inside a string, raw or escaped; an escaped backslash before `x` or `u`; a surrogate pair
          assert_equal(
            { a: '/', b: '/', c: '\\x', d: '\\uD800', e: "\u{1F600}", f: 'é', g: "\u0000" },
            Triauth::Helpers.safe_parse_json('{"a":"/","b":"\\/","c":"\\\\x","d":"\\\\uD800","e":"\\uD83D\\uDE00","f":"\\u00e9","g":"\\u0000"}')
          )
          assert_equal({ 'a/b': 1 }, Triauth::Helpers.safe_parse_json('{"a/b":1}'))
          # rejected by JSON.parse in JS (a SyntaxError), admitted by the json gem: the gate makes each a parser failure here
          [
            # comments, and a stray slash
            '{"a":1}/*c*/', '/*c*/{"a":1}', '{"a":/*c*/1}', "{\"a\":1}//c\n", '{"a" /*c*/ :1}', '{"a":1}/',
            # unknown or short escapes
            '{"a":"\\x41"}', '{"a":"\\a"}', '{"a":"\\\'"}', '{"a":"\\u"}', '{"a":"\\u12"}',
            # a surrogate escape outside a high-then-low pair (the gate's third construct; the port-only test below pins the full set)
            '{"a":"\\uD800\\u0041"}', '{"a":"\\uD800\\uD800"}', '{"a":"\\uD800"}', '{"\\uD800":1}'
          ].each do |source|
            assert_raises(JSON::ParserError, source) do
              Triauth::Helpers.safe_parse_json(source)
            end
          end
        end

        it 'rejects a lone or mis-paired surrogate escape at the source gate, as the reference rejects the surrogate code point after parsing (port-only)' do
          # JS parses each of these into a string holding a lone surrogate (one UTF-16 unit of category Cs) and refuses it
          # in `safeParseJson`'s string-value check; no Ruby String can hold one, and the json gem alone would refuse
          # `\uD800`, pair it with any `\u` escape that follows, or spell a lone `\uDC00` as the ill-formed bytes ED B0 80,
          # so `JSON_STRICT_SOURCE_REGEXP` refuses the escapes before parsing: a parse failure on both sides
          [
            '{"a":"\\uD800"}', '{"a":"\\ud800"}', '{"a":"\\uDBFF"}',                # a lone high surrogate
            '{"a":"\\uDC00"}', '{"a":"\\uDFFF"}', '{"a":"x\\uDC00y"}',              # a lone low surrogate
            '{"a":"\\uD800A"}', '{"a":"\\uD800\\u0041"}', '{"a":"\\uD800\\uD800"}', # a high surrogate followed by a raw character or a non-low escape
            '{"a":"\\uDC00\\uD800"}', '{"a":"\\uDC00\\uDC00"}',                     # low-then-high, low-then-low
            '{"a":"\\uD800\\uD83D\\uDE00"}',                                        # a lone high before a valid pair
            '{"a":["\\uDFFF"]}', '{"a":{"b":"\\uD800"}}',                           # inside an Array and a nested Hash
            '{"\\uD800":1}', '{"\\uDC00":1}', '{"a":{"\\uDFFF":1}}'                  # in a key
          ].each do |source|
            err = assert_raises(JSON::ParserError, source) do
              Triauth::Helpers.safe_parse_json(source)
            end
            assert_equal 'source is not strict JSON (a comment, an unknown escape or a surrogate escape outside a pair)', err.message, source
          end
          # a surrogate pair, an escaped backslash before `ud800` (spelled `\\` or as the escape of the backslash itself), a
          # double-escaped backslash before a pair, and a literal U+FFFD are the JS values
          assert_equal(
            { a: "\u{1F600}", b: '\\ud800', c: '\\ud800', d: "\u{10FFFF}", e: "\\\u{1F600}" },
            Triauth::Helpers.safe_parse_json('{"a":"\\uD83D\\uDE00","b":"\\\\ud800","c":"\\u005cud800","d":"\\uDBFF\\uDFFF","e":"\\\\\\uD83D\\uDE00"}')
          )
          assert_equal({ f: "\u{FFFD}" }, Triauth::Helpers.safe_parse_json("{\"f\":\"\u{FFFD}\"}"))
        end
      end

      describe 'orderedEntries (port-only)' do
        it 'lists array-index keys first in numeric order, then the rest in insertion order' do
          hash = { b: 'B', '10': 'ten', a: 'A', '2': 'two', '01': 'oh-one', '4294967295': 'not-an-index', '4294967294': 'last-index' }
          assert_equal(
            [[:'2', 'two'], [:'10', 'ten'], [:'4294967294', 'last-index'], [:b, 'B'], [:a, 'A'], [:'01', 'oh-one'], [:'4294967295', 'not-an-index']],
            Triauth::Helpers.ordered_entries(hash)
          )
          assert_equal [], Triauth::Helpers.ordered_entries({})
          assert_equal [[:'0', 1], [:x, 2]], Triauth::Helpers.ordered_entries({ x: 2, '0': 1 })
        end
      end

      describe 'objectAssign (port-only)' do
        it 'merges Hashes and spreads Strings and Arrays under index keys; nil, booleans, numbers and Symbols contribute nothing' do
          assert_equal({}, Triauth::Helpers.object_assign(nil))
          assert_equal({}, Triauth::Helpers.object_assign(5))
          assert_equal({}, Triauth::Helpers.object_assign(true))
          assert_equal({}, Triauth::Helpers.object_assign(false))
          assert_equal({}, Triauth::Helpers.object_assign(:sym))
          assert_equal({}, Triauth::Helpers.object_assign([]))
          assert_equal({}, Triauth::Helpers.object_assign(''))
          assert_equal({}, Triauth::Helpers.object_assign(Object.new))
          assert_equal({ '0': 'identifier' }, Triauth::Helpers.object_assign(['identifier']))
          assert_equal({ '0': 'a', '1': 'b' }, Triauth::Helpers.object_assign('ab'))
          assert_equal({ a: 1 }, Triauth::Helpers.object_assign({ a: 1 }))
          assert_equal({}, Triauth::Helpers.object_assign)
        end

        it 'lets a later source override, a nil value included, and returns a new Hash each time' do
          defaults = { timeout: 5, retries: 3 }
          merged = Triauth::Helpers.object_assign({}, defaults, { timeout: 1 }, { retries: nil })
          assert_equal({ timeout: 1, retries: nil }, merged)
          assert_equal({ timeout: 5, retries: 3 }, defaults)
          assert_equal({ '0': 'z', a: 1 }, Triauth::Helpers.object_assign({ '0': 'x', a: 1 }, 'z'))
          refute_same Triauth::Helpers.merge_config, Triauth::Helpers.merge_config
          assert_equal Triauth.config, Triauth::Helpers.merge_config
          assert_equal 'corr', Triauth::Helpers.merge_config({ cid: 'corr' })[:cid]
          assert_nil Triauth.config[:cid]
        end
      end

      describe 'percentDecode / encodeUriComponent (port-only)' do
        it 'percentDecode keeps the decodeURIComponent accept-set: two hex digits per escape, well-formed UTF-8, no + handling' do
          assert_equal 'AĄ', Triauth::Helpers.percent_decode('%41%C4%84')
          assert_equal 'aĄ', Triauth::Helpers.percent_decode('%61%c4%84')
          assert_nil Triauth::Helpers.percent_decode('%4')
          assert_nil Triauth::Helpers.percent_decode('%')
          assert_nil Triauth::Helpers.percent_decode('%zz')
          assert_nil Triauth::Helpers.percent_decode('%E9') # ill-formed: a lone latin-1 byte
          assert_nil Triauth::Helpers.percent_decode('%C3%A9%A9') # a stray continuation byte
          assert_nil Triauth::Helpers.percent_decode('%ED%A0%80') # an encoded surrogate
          assert_equal 'a+b', Triauth::Helpers.percent_decode('a+b')
          assert_equal 'é 😀', Triauth::Helpers.percent_decode('é %F0%9F%98%80')
          assert_equal '', Triauth::Helpers.percent_decode('')
          assert_nil Triauth::Helpers.percent_decode(nil)
          assert_nil Triauth::Helpers.percent_decode("a\xE9".dup.force_encoding('UTF-8'))
          assert_equal Encoding::UTF_8, Triauth::Helpers.percent_decode('%41').encoding
        end

        it 'encodeUriComponent keeps the JS unreserved set and percent-encodes the UTF-8 bytes of everything else in uppercase hex' do
          assert_equal 'a%20b%2F%C3%A9', Triauth::Helpers.encode_uri_component('a b/é')
          unreserved = "AZaz09-_.!~*'()"
          assert_equal unreserved, Triauth::Helpers.encode_uri_component(unreserved)
          assert_equal '%3B%2C%2F%3F%3A%40%26%3D%2B%24%23%25%22%3C%3E%5B%5D%7B%7D%7C%5C%5E%60%00%0A', Triauth::Helpers.encode_uri_component(";,/?:@&=+$#%\"<>[]{}|\\^`\u0000\n")
          assert_equal '%F0%9F%98%80', Triauth::Helpers.encode_uri_component(edge[:emoji])
          assert_equal Encoding::UTF_8, Triauth::Helpers.encode_uri_component('é').encoding
          assert_raises(TypeError) { Triauth::Helpers.encode_uri_component("\xE9".dup.force_encoding('UTF-8')) }
          assert_raises(TypeError) { Triauth::Helpers.encode_uri_component(nil) }
        end
      end

      describe 'randomString contract (port-only)' do
        it 'requests ceil(len * 0.75) + 1 bytes and fails closed on a short or non-String return' do
          requested = []
          source = lambda do |n|
            requested.push(n)
            "\x00".b * n
          end
          assert_equal 'A' * 24, Triauth::Helpers.random_string(24, { randomSource: source })
          assert_equal [19], requested
          assert_equal 'AAAA', Triauth::Helpers.random_string(4, { randomSource: source })
          assert_equal [19, 4], requested

          err = assert_raises(ArgumentError) { Triauth::Helpers.random_string(24, { randomSource: ->(n) { "\x00".b * (n - 1) } }) }
          assert_equal 'randomSource must return 19 bytes', err.message
          assert_raises(ArgumentError) { Triauth::Helpers.random_string(24, { randomSource: ->(n) { "\x00".b * (n + 1) } }) }
          assert_raises(ArgumentError) { Triauth::Helpers.random_string(24, { randomSource: ->(n) { Array.new(n, 0) } }) }
          assert_raises(ArgumentError) { Triauth::Helpers.random_string(24, { randomSource: ->(_n) {} }) }

          # the default source is SecureRandom: base64url characters only, fresh every call
          a = Triauth::Helpers.random_string(24, { randomSource: nil })
          b = Triauth::Helpers.random_string(24, { randomSource: nil })
          assert_match(/\A[A-Za-z0-9\-_]{24}\z/, a)
          refute_equal a, b
          assert_equal 0, Triauth::Helpers.random_string(0, { randomSource: nil }).length
        end
      end

      describe 'createLRUCache (port-only)' do
        it 'evicts the oldest entry at size, get refreshes recency, resize trims' do
          cache = Triauth::Helpers.create_lru_cache(2)
          assert_nil cache.get('missing')
          cache.set('a', 1)
          cache.set('b', 2)
          assert_equal 1, cache.get('a') # `a` is now the most recently used
          cache.set('c', 3) # evicts `b`, the oldest
          assert_nil cache.get('b')
          assert_equal 1, cache.get('a')
          assert_equal 3, cache.get('c')

          cache.set('a', 10) # an update keeps one entry and refreshes it
          assert_equal 10, cache.get('a')
          cache.set('d', 4) # evicts `c`
          assert_nil cache.get('c')
          assert_equal [10, 4], [cache.get('a'), cache.get('d')]

          cache.resize(1) # trims to the most recent entry (`d`)
          assert_nil cache.get('a')
          assert_equal 4, cache.get('d')
          cache.set('e', 5)
          assert_nil cache.get('d')
          assert_equal 5, cache.get('e')

          # the default size is 1024
          big = Triauth::Helpers.create_lru_cache
          1025.times { |i| big.set("k#{i}", i) }
          assert_nil big.get('k0')
          assert_equal 1, big.get('k1')
          assert_equal 1024, big.get('k1024')
          refute_nil cache.get('e') # a cached false is a value, nil means absent
          cache.set('f', false)
          assert_equal false, cache.get('f')
        end
      end

      describe 'strict decoders and encoders (port-only)' do
        it 'base64UrlToUint8 accepts exactly one encoding per byte sequence' do
          assert_equal '', Triauth::Helpers.base64url_to_uint8('')
          assert_equal 'A', Triauth::Helpers.base64url_to_uint8('QQ')
          assert_equal [0xFB, 0xFF, 0xBF], Triauth::Helpers.base64url_to_uint8('-_-_').bytes
          assert_equal Encoding::ASCII_8BIT, Triauth::Helpers.base64url_to_uint8('QQ').encoding

          err = assert_raises(TypeError) { Triauth::Helpers.base64url_to_uint8('QR') } # payload in the unused trailing bits
          assert_equal 'Non-canonical base64url input', err.message
          assert_raises(TypeError) { Triauth::Helpers.base64url_to_uint8('QUJ') }
          ['A', 'QQ==', 'QQ=', 'Q Q', "QQ\n", '+/', 'Q+', nil, 42, "\xC3".dup.force_encoding('UTF-8')].each do |bad|
            err = assert_raises(TypeError, bad.inspect) { Triauth::Helpers.base64url_to_uint8(bad) }
            assert_equal 'Invalid base64url input', err.message, bad.inspect
          end
        end

        it 'stringToUtf8Bytes and utf8BytesToString reject non-strings with the triauth-js messages' do
          [nil, 5, [0x41], :sym, { a: 1 }].each do |bad|
            err = assert_raises(TypeError, bad.inspect) { Triauth::Helpers.utf8_bytes_to_string(bad) }
            assert_equal 'utf8BytesToString expects a Uint8Array', err.message
            err = assert_raises(TypeError, bad.inspect) { Triauth::Helpers.string_to_utf8_bytes(bad) }
            assert_equal 'stringToUtf8Bytes expects a string', err.message
          end
          err = assert_raises(TypeError) { Triauth::Helpers.utf8_bytes_to_string("\xE9".b) }
          assert_equal 'Ill-formed UTF-8 bytes', err.message
          assert_equal Encoding::ASCII_8BIT, Triauth::Helpers.string_to_utf8_bytes('é').encoding
          assert_equal Encoding::UTF_8, Triauth::Helpers.utf8_bytes_to_string("\xC3\xA9".b).encoding
          # the decoded string is a copy: the binary input keeps its encoding
          bytes = "\xC3\xA9".b
          Triauth::Helpers.utf8_bytes_to_string(bytes)
          assert_equal Encoding::ASCII_8BIT, bytes.encoding
        end

        it 'uInt8ArrayToBase32, arrayBufferToBase64 and arrayBufferToBase64Url match the RFC 4648 vectors' do
          base32 = { '' => '', 'f' => 'MY', 'fo' => 'MZXQ', 'foo' => 'MZXW6', 'foob' => 'MZXW6YQ', 'fooba' => 'MZXW6YTB', 'foobar' => 'MZXW6YTBOI' }
          base32.each do |input, expected|
            assert_equal expected, Triauth::Helpers.uint8_array_to_base32(input.b), input # unpadded, as in triauth-js
          end
          base64 = { '' => '', 'f' => 'Zg==', 'fo' => 'Zm8=', 'foo' => 'Zm9v', 'foob' => 'Zm9vYg==', 'fooba' => 'Zm9vYmE=', 'foobar' => 'Zm9vYmFy' }
          base64.each do |input, expected|
            assert_equal expected, Triauth::Helpers.array_buffer_to_base64(input.b), input
            assert_equal expected.delete('='), Triauth::Helpers.array_buffer_to_base64url(input.b), input
          end
          assert_equal '+/8=', Triauth::Helpers.array_buffer_to_base64([0xFB, 0xFF].pack('C*'))
          assert_equal '-_8', Triauth::Helpers.array_buffer_to_base64url([0xFB, 0xFF].pack('C*'))
          # a UTF-8 String is read as its bytes, like `new Uint8Array(b)` over a buffer
          assert_equal 'w6k', Triauth::Helpers.array_buffer_to_base64url('é')
          assert_equal 'YOUQ', Triauth::Helpers.uint8_array_to_base32("\xC3\xA9".b)

          # the 32-bit mask of the accumulators is the JS `<<` semantics: long inputs round-trip byte-exactly
          long = (0..255).to_a.pack('C*') * 64
          assert_equal long, Triauth::Helpers.base64url_to_uint8(Triauth::Helpers.array_buffer_to_base64url(long))
        end
      end

      describe 'sha256 / hmacSha256 (port-only)' do
        it 'computes the known SHA-256 and HMAC-SHA-256 vectors' do
          assert_equal 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0', Triauth::Helpers.sha256('abc') # NIST: ba7816bf...15ad
          assert_equal '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU', Triauth::Helpers.sha256('') # e3b0c442...b855
          assert_equal Triauth::Helpers.array_buffer_to_base64url(OpenSSL::Digest::SHA256.digest("\xC3\xA9".b)), Triauth::Helpers.sha256('é')
          assert_raises(TypeError) { Triauth::Helpers.sha256(nil) }
          assert_raises(TypeError) { Triauth::Helpers.sha256("\xE9".dup.force_encoding('UTF-8')) }

          # RFC 4231 test case 2
          mac = Triauth::Helpers.hmac_sha256('Jefe'.b, 'what do ya want for nothing?'.b)
          assert_equal '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843', mac.unpack1('H*')
          assert_equal 32, mac.bytesize
          assert_equal Encoding::ASCII_8BIT, mac.encoding
        end
      end

      describe 'clone (port-only)' do
        it 'deep-copies Hashes, Arrays and Strings, sharing no nested container, and returns immediates as they are' do
          original = { a: ['x', { b: +'y' }], c: +'z', d: 1, e: nil, f: true, g: 1.5, h: :sym }
          copy = Triauth::Helpers.clone(original)
          assert_equal original, copy
          refute_same original, copy
          refute_same original[:a], copy[:a]
          refute_same original[:a][1], copy[:a][1]
          refute_same original[:a][1][:b], copy[:a][1][:b]
          refute_same original[:c], copy[:c]
          copy[:a][1][:b] << '!'
          copy[:a].push('new')
          copy[:c] << '!'
          assert_equal({ a: ['x', { b: 'y' }], c: 'z', d: 1, e: nil, f: true, g: 1.5, h: :sym }, original)

          [nil, 1, 1.5, true, false, :sym].each { |value| assert_same value, Triauth::Helpers.clone(value) }
          assert_equal [], Triauth::Helpers.clone([])
          assert_equal({}, Triauth::Helpers.clone({}))
          refute Triauth::Helpers.clone('frozen').frozen?
        end
      end

      describe 'earliest (port-only)' do
        it 'follows the JS nullish rules: only nil is absent, 0 is a timestamp' do
          assert_nil Triauth::Helpers.earliest(nil, nil)
          assert_equal 3, Triauth::Helpers.earliest(nil, 3)
          assert_equal 5, Triauth::Helpers.earliest(5, nil)
          assert_equal 3, Triauth::Helpers.earliest(5, 3)
          assert_equal 3, Triauth::Helpers.earliest(3, 5)
          assert_equal 0, Triauth::Helpers.earliest(0, nil)
          assert_equal 0, Triauth::Helpers.earliest(nil, 0)
          assert_equal 0, Triauth::Helpers.earliest(0, 7)
        end
      end

      describe 'hasOnlyKnownProperties (port-only)' do
        it 'accepts only Hashes whose keys are whitelisted; a nil value passes, as null does in triauth-js (no undefined here)' do
          whitelist = %i[identifier callbackUrl]
          assert_equal true, Triauth::Helpers.has_only_known_properties({}, whitelist)
          assert_equal true, Triauth::Helpers.has_only_known_properties({ identifier: 'john@triauthdemo.org' }, whitelist)
          assert_equal true, Triauth::Helpers.has_only_known_properties({ identifier: nil }, whitelist)
          assert_equal true, Triauth::Helpers.has_only_known_properties({ identifier: nil }, whitelist, false)
          assert_equal false, Triauth::Helpers.has_only_known_properties({ identifier: 'x', extra: 1 }, whitelist)
          assert_equal false, Triauth::Helpers.has_only_known_properties({ 'identifier' => 'x' }, whitelist) # a String key is an unknown key
          [nil, [], ['identifier'], 'identifier', 5, true, :identifier].each do |value|
            assert_equal false, Triauth::Helpers.has_only_known_properties(value, whitelist), value.inspect
          end
        end
      end

      describe 'asciiLowercase / isBase64UrlString (port-only)' do
        it 'asciiLowercase maps only A-Z (never the KELVIN SIGN or any other case mapping)' do
          assert_equal 'abc-xyz_09', Triauth::Helpers.ascii_lowercase('ABC-xyZ_09')
          assert_equal "#{edge[:kelvin]}elvin É ß", Triauth::Helpers.ascii_lowercase("#{edge[:kelvin]}ELVIN É ß")
          assert_equal '', Triauth::Helpers.ascii_lowercase('')
        end

        it 'isBase64UrlString admits the padding-free base64url alphabet only, with absolute anchors' do
          assert_equal true, Triauth::Helpers.is_base64url_string('AZaz09-_')
          assert_equal false, Triauth::Helpers.is_base64url_string('')
          assert_equal false, Triauth::Helpers.is_base64url_string('a+b')
          assert_equal false, Triauth::Helpers.is_base64url_string('a/b')
          assert_equal false, Triauth::Helpers.is_base64url_string('ab==')
          assert_equal false, Triauth::Helpers.is_base64url_string("ab\n")
          assert_equal false, Triauth::Helpers.is_base64url_string("ab\nab")
          assert_equal false, Triauth::Helpers.is_base64url_string('ab ')
          assert_equal false, Triauth::Helpers.is_base64url_string(edge[:eacute])
          assert_equal false, Triauth::Helpers.is_base64url_string("\xE9".dup.force_encoding('UTF-8'))
          [nil, 42, [], {}, :ab].each { |value| assert_equal false, Triauth::Helpers.is_base64url_string(value), value.inspect }
        end
      end

      describe 'dateNow (port-only)' do
        it 'reads the wall clock in Integer milliseconds and can be frozen by redefining the singleton method' do
          before_ms = (Time.now.to_f * 1000).floor
          now = Triauth::Helpers.date_now
          after_ms = (Time.now.to_f * 1000).ceil
          assert_kind_of Integer, now
          assert_operator now, :>=, before_ms
          assert_operator now, :<=, after_ms

          saved = Triauth::Helpers.method(:date_now)
          begin
            Triauth::Helpers.define_singleton_method(:date_now) { 1_700_000_000_000 }
            assert_equal 1_700_000_000_000, Triauth::Helpers.date_now
          ensure
            Triauth::Helpers.define_singleton_method(:date_now, saved)
          end
          assert_operator Triauth::Helpers.date_now, :>=, now

          # the monotonic clock is a Float and moves forward
          t1 = Triauth::Helpers.now
          t2 = Triauth::Helpers.now
          assert_kind_of Float, t1
          assert_operator t2, :>=, t1
        end
      end

      describe 'fetch (port-only)' do
        # Serves one plain-TCP connection on 127.0.0.1: reads the request head, hands the socket to `handler`, then
        # closes it. Returns the port and the server thread (join it after the client is done).
        define_method(:serve_once) do |&handler|
          server = TCPServer.new('127.0.0.1', 0)
          port = server.addr[1]
          thread = Thread.new do
            sock = server.accept
            begin
              loop do
                line = sock.gets
                break if line.nil? || line == "\r\n"
              end
              handler.call(sock)
            ensure
              sock.close
              server.close
            end
          end
          thread.report_on_exception = false
          [port, thread]
        end

        it 'yields ok, status, the lowercase headers and the body chunks of a 200 response, and returns the block value' do
          port, thread = serve_once do |sock|
            sock.write("HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\nX-Twice: a\r\nX-Twice: b\r\nTransfer-Encoding: chunked\r\n\r\n")
            sock.write("6\r\nchunk1\r\n")
            sleep 0.1
            sock.write("6\r\nchunk2\r\n0\r\n\r\n")
          end
          chunks = []
          result = Triauth::Helpers.fetch("http://127.0.0.1:#{port}/dns-query?name=a&type=TXT", { headers: { 'Accept' => 'application/dns-json', 'Accept-Encoding' => 'identity' }, timeout: 2000 }) do |response|
            response.each_chunk { |bytes| chunks.push(bytes.dup) }
            [response.ok, response.status, response.headers['content-type'], response.headers['x-twice'], response.headers.key?('Content-Type')]
          end
          thread.join(5)
          assert_equal [true, 200, 'application/dns-json', 'a, b', false], result
          assert_equal %w[chunk1 chunk2], chunks
          assert(chunks.all? { |chunk| chunk.encoding == Encoding::ASCII_8BIT })
        end

        it 'does not follow a redirect: a 301 answer is yielded with ok false' do
          port, thread = serve_once do |sock|
            sock.write("HTTP/1.1 301 Moved Permanently\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\n\r\n")
          end
          result = Triauth::Helpers.fetch("http://127.0.0.1:#{port}/", { timeout: 2000 }) do |response|
            [response.ok, response.status, response.headers['location']]
          end
          thread.join(5)
          assert_equal [false, 301, 'http://127.0.0.1:1/elsewhere'], result
        end

        it 'raises Net::ReadTimeout within about timeout ms when the server never answers, with no transport-level retry' do
          port, thread = serve_once do |sock|
            sock.wait_readable(3) # the client gives up first and closes
          end
          started = Triauth::Helpers.now
          assert_raises(Net::ReadTimeout) do
            Triauth::Helpers.fetch("http://127.0.0.1:#{port}/", { timeout: 300 }) { |_response| flunk 'no response expected' }
          end
          elapsed = Triauth::Helpers.now - started
          thread.join(5)
          assert_operator elapsed, :>=, 250
          assert_operator elapsed, :<, 550 # one attempt only: a retry would take 600 ms or more
        end

        it 'closes the connection when the block raises (the server sees EOF)' do
          saw_eof = nil
          port, thread = serve_once do |sock|
            sock.write("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nchunk1") # half of the declared body
            saw_eof = !sock.wait_readable(3).nil? && sock.eof?
          end
          err = assert_raises(RuntimeError) do
            Triauth::Helpers.fetch("http://127.0.0.1:#{port}/", { timeout: 2000 }) do |response|
              response.each_chunk { |bytes| raise 'DoH response exceeds size limit' if bytes.bytesize > 0 }
            end
          end
          thread.join(5)
          assert_equal 'DoH response exceeds size limit', err.message
          assert_equal true, saw_eof
        end

        it 'builds the https transport with peer verification, every phase bounded by the timeout and no retry (Net::HTTP.new stubbed, nothing is connected)' do
          original_new = Net::HTTP.method(:new)
          captured = nil
          Net::HTTP.define_singleton_method(:new) do |*args|
            captured = original_new.call(*args)
            captured.define_singleton_method(:start) { |&_block| raise 'stopped before connecting' }
            captured
          end
          begin
            err = assert_raises(RuntimeError) do
              Triauth::Helpers.fetch('https://dns.example.invalid/dns-query?name=a', { timeout: 1500 }) { |_response| flunk 'unreachable' }
            end
            assert_equal 'stopped before connecting', err.message
          ensure
            Net::HTTP.define_singleton_method(:new, original_new)
          end
          assert_equal ['dns.example.invalid', 443], [captured.address, captured.port]
          assert captured.use_ssl?
          assert_equal OpenSSL::SSL::VERIFY_PEER, captured.verify_mode
          assert_equal [1.5, 1.5, 1.5], [captured.open_timeout, captured.read_timeout, captured.write_timeout]
          assert_equal 0, captured.max_retries

          # an http URL without a timeout keeps Net::HTTP's defaults and no TLS
          Net::HTTP.define_singleton_method(:new) do |*args|
            captured = original_new.call(*args)
            captured.define_singleton_method(:start) { |&_block| raise 'stopped before connecting' }
            captured
          end
          begin
            assert_raises(RuntimeError) { Triauth::Helpers.fetch('http://127.0.0.1:8053/x') { |_response| flunk 'unreachable' } }
          ensure
            Net::HTTP.define_singleton_method(:new, original_new)
          end
          assert_equal ['127.0.0.1', 8053], [captured.address, captured.port]
          refute captured.use_ssl?
          assert_equal [60, 60, 60], [captured.open_timeout, captured.read_timeout, captured.write_timeout]
        end
      end
    end
  end
end

TestInternals.helpers if __FILE__ == $PROGRAM_NAME
