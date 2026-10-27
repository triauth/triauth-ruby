# frozen_string_literal: true

# Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0


require 'json'
require 'openssl'
require 'securerandom'
require 'net/http'
require 'uri'
require_relative 'protocol'
require_relative 'config'

module Triauth
  # Static helpers shared across the library.
  class Helpers
    BASE64URL_REGEXP = /\A[A-Za-z0-9\-_]+\z/
    BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    BASE64URL_VALUES = lambda do
      values = Array.new(123, 0) # indexed by char code; 'z' (the highest) is 122
      64.times do |i|
        values[BASE64URL_ALPHABET.getbyte(i)] = i
      end
      return values
    end.call
    DOMAIN_NAME_REGEXP = /\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\z/
    XN_LABEL_REGEXP = /(\A[xX][nN]--)|(\.[xX][nN]--)/                                  # a Punycode (xn--) label, leading or after a dot
    URL_HOST_LABEL_REGEXP = /\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/                 # one lowercase LDH host label, 1-63 chars, no edge hyphens
    URL_NUMERIC_LABEL_REGEXP = /\A(?:[0-9]+|0[xX][0-9a-fA-F]*)\z/                      # an all-digits or 0x-hex label, an IPv4 notation when final
    URL_IPV4_QUAD_REGEXP = /\A(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\z/ # a canonical dotted-quad IPv4 host: four decimal octets 0-255, no leading zeros
    URL_DOT_SEGMENT_REGEXP = /\A(?:\.|%2[eE]){1,2}\z/                                  # a "." or ".." path segment, %2e spellings included
    URL_PATH_REGEXP = %r{\A[A-Za-z0-9\-._~!$&'()*+,;=:@/%]*\z}                         # RFC 3986 pchar + "/" ("%" is a plain char here; "|" is not a URL character)
    URL_QUERY_REGEXP = %r{\A[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]+\z}                       # the path characters + "?" also the fragment charset
    NORMAL_STRING_REGEXP = %r{\A[\p{L}\p{N} ~!@#$%^&*()_\-+={}\[\]|\\:;"'<,>.?/]+\z}   # the Unicode property escape \p{L} matches any kind of letter from any language, \p{N} any number.
    # `UNPAIRED_SURROGATE_REGEXP` (`\p{Cs}`) has no counterpart: an ill-formed string is "not a string" (`Helpers.is_string`, the encoding-validity gate behind `is_well_formed_string`)
    LOOKUP_CODE_REGEXP = /\A[A-Z0-9]{16}\z/
    PROTOTYPE_NAMES = %w[__proto__ constructor prototype].freeze                   # the prototype-poisoning names, never a JSON member name
    P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff # the P-256 field prime p
    # `#P256_B` (the P-256 curve coefficient b, a = -3) has no counterpart: the curve equation is OpenSSL's (`decode_p256_public_key`)
    # The json gem parses a wider grammar than `JSON.parse` of JS: `/* */` and `//` comments between tokens, an unknown
    # escape such as `\x` inside a string (read as `x`), and a high-surrogate `\u` escape paired with whatever `\u` escape
    # follows it (a lone high one it refuses, a lone low one it spells as ill-formed bytes). This gate admits only the JS
    # grammar of the first two constructs - outside a string literal no `/`, inside one only the JSON escapes - and refuses
    # every surrogate escape outside a high-then-low pair: the reference parses such an escape into a surrogate code point
    # and refuses the string (`safe_parse_json`, the string-value check), which no Ruby String can hold, so the same inputs
    # are a parse failure here, on the source (a pair is one code point on both sides). The gate is linear in the source
    # length: every alternative is decided by a bounded prefix (its first character, or the six characters of a `\u` escape).
    JSON_STRICT_SOURCE_REGEXP = %r{\A(?:[^"/]|"(?:[^"\\]|\\["\\/bfnrt]|\\u[Dd][89ABab][0-9A-Fa-f]{2}\\u[Dd][C-Fc-f][0-9A-Fa-f]{2}|\\u(?![Dd][89A-Fa-f])[0-9A-Fa-f]{4})*")*\z}
    private_constant :BASE64URL_REGEXP, :BASE32_ALPHABET, :BASE64_ALPHABET, :BASE64URL_ALPHABET, :BASE64URL_VALUES,
                     :DOMAIN_NAME_REGEXP, :XN_LABEL_REGEXP, :URL_HOST_LABEL_REGEXP, :URL_NUMERIC_LABEL_REGEXP,
                     :URL_IPV4_QUAD_REGEXP, :URL_DOT_SEGMENT_REGEXP, :URL_PATH_REGEXP, :URL_QUERY_REGEXP,
                     :NORMAL_STRING_REGEXP, :LOOKUP_CODE_REGEXP, :PROTOTYPE_NAMES, :P256_P, :JSON_STRICT_SOURCE_REGEXP

    # `#ENCODER` and `#DECODER` have no counterpart: `string_to_utf8_bytes` and `utf8_bytes_to_string` work on the String itself

    # Returns the current time in milliseconds, for duration measurements.
    #
    # Monotonic (`Process::CLOCK_MONOTONIC`); durations only, never the wall clock.
    #
    # @return [Float] a millisecond timestamp.
    def self.now
      # the `?? Date.now()` fallback has no counterpart: `CLOCK_MONOTONIC` always exists
      return Process.clock_gettime(Process::CLOCK_MONOTONIC, :float_millisecond)
    end

    # Returns the earlier of two timestamps, tolerating either being nil.
    #
    # @param a [Integer, nil] a timestamp, or nil.
    # @param b [Integer, nil] a timestamp, or nil.
    #
    # @return [Integer, nil] the earlier of the two, or whichever one is set.
    def self.earliest(a, b)
      return [a, b].min if !a.nil? && !b.nil?

      return a.nil? ? b : a
    end

    # Verifies DNS record options against a schema of allowed critical options and values.
    #
    # Non-`x-` prefixed options are critical: each must be whitelisted in the schema and match one of its
    # allowed values (strings, regexps, or predicate callables returning exactly `true`). `x-` prefixed
    # options are experimental and pass as long as they are normal strings.
    #
    # @param options [Hash{Symbol => Object}] the options as parsed from a DNS record.
    # @param options_schema [Hash{Symbol => Array<String, Regexp, Proc>}] a map of option keys to arrays of allowed values (strings, regexps, or predicates).
    #
    # @return [Boolean] true when every option is acceptable, false otherwise.
    def self.verify_options_schema(options, options_schema)
      options.each do |option_key, option_val|
        # whitelisted critical options and values
        next if Helpers.is_string(option_val) &&
                options_schema.key?(option_key) &&
                options_schema[option_key].any? { |v| (Helpers.is_string(v) && option_val == v) || (v.is_a?(Regexp) && v.match?(option_val)) || (v.respond_to?(:call) && v.call(option_val) == true) }

        # experimental options prefixed with 'x-' are allowed as long as they are generally sane
        next if Helpers.is_normal_string(option_key.to_s) &&
                Helpers.is_normal_string(option_val) &&
                option_key.to_s[0] == 'x' &&
                option_key.to_s[1] == '-'

        # unknown or invalid critical option - reject
        return false
      end

      return true
    end

    # Returns a deep copy of the given JSON-shaped value (API results, parsed records).
    #
    # A recursive copy of `Hash`, `Array` and `String` values; other immediates are returned as they are.
    #
    # @param value [Object] A JSON-shaped value to copy.
    #
    # @return [Object] a deep copy sharing no mutable state with the input.
    def self.clone(value)
      # the `structuredClone` detection and the JSON round-trip have no counterpart: the recursive copy below is the port of both
      case value
      when Hash
        return value.to_h { |k, v| [k, clone(v)] }
      when Array
        return value.map { |v| clone(v) }
      when String
        return value.dup
      else
        return value
      end
    end

    # Encodes a given byte array into a Base32 encoded string.
    #
    # @param b [String] A byte array (binary String) containing the message to be encoded as a base32 string.
    #
    # @return [String] base32 representation of the given byte array
    def self.uint8_array_to_base32(b)
      alphabet = BASE32_ALPHABET
      bytes = b

      bits = 0
      value = 0
      rv = +""

      bytes.bytesize.times do |i|
        value = ((value << 8) | bytes.getbyte(i)) & 0xFFFFFFFF # the JS `<<` works on 32-bit integers: the mask keeps the accumulator bounded the same way
        bits += 8

        # 5-bits per character in base32
        while bits >= 5
          rv << alphabet[(value >> (bits - 5)) & 31]
          bits -= 5
        end
      end

      # anything that's left needs to be also encoded
      if bits > 0
        rv << alphabet[(value << (5 - bits)) & 31]
      end

      return rv
    end

    # Encodes a given byte array buffer into a Base64 encoded string.
    #
    # @param b [String] A byte array (binary String) that contains the message (bytes) to be encoded as base64 string.
    #
    # @return [String] base64 representation of the given array buffer
    def self.array_buffer_to_base64(b)
      alphabet = BASE64_ALPHABET
      bytes = b # `new Uint8Array(b)`: the bytes are read from the String itself

      rv = +''

      # 3 bytes make 4 characters; a final partial group is '='-padded
      (0...bytes.bytesize).step(3) do |i|
        b0 = bytes.getbyte(i)
        b1 = i + 1 < bytes.bytesize ? bytes.getbyte(i + 1) : 0
        b2 = i + 2 < bytes.bytesize ? bytes.getbyte(i + 2) : 0

        rv << alphabet[b0 >> 2]
        rv << alphabet[((b0 & 0x03) << 4) | (b1 >> 4)]
        rv << (i + 1 < bytes.bytesize ? alphabet[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=')
        rv << (i + 2 < bytes.bytesize ? alphabet[b2 & 0x3f] : '=')
      end

      return rv
    end

    # Encodes a given byte array buffer into a Base64URL encoded string.
    #
    # @param b [String] A byte array (binary String) that contains the message (bytes) to be encoded as base64url string.
    #
    # @return [String] base64url representation of the given array buffer
    def self.array_buffer_to_base64url(b)
      rv = array_buffer_to_base64(b)
      return rv.gsub('+', '-').gsub('/', '_').sub(/=+\z/, '')
    end

    # Converts the passed base64url encoded string into a binary String of its individual bytes.
    #
    # @param s [String] A base64url encoded string.
    #
    # @return [String] a binary String with byte values representing the characters of passed string.
    #
    # @raise [TypeError] when the string is not base64url, or is a non-canonical encoding
    #                    (an impossible length, or payload in the final character's unused bits).
    def self.base64url_to_uint8(s)
      # Canonical decode: only the padding-free base64url alphabet, only
      # possible lengths, and no payload in the final character's unused bits —
      # every byte sequence has exactly one accepted encoding.
      if !Helpers.is_string(s) || s.length % 4 == 1 || !/\A[A-Za-z0-9\-_]*\z/.match?(s)
        raise TypeError, 'Invalid base64url input'
      end

      values = BASE64URL_VALUES
      rv = Array.new(s.length * 3 / 4, 0).pack('C*') # `Math.floor(s.length * 3 / 4)`: the Integer division floors

      bits = 0
      value = 0
      index = 0

      s.length.times do |i|
        value = ((value << 6) | values[s.getbyte(i)]) & 0xFFFFFFFF # the JS `<<` works on 32-bit integers: the mask keeps the accumulator bounded the same way
        bits += 6

        # 8 accumulated bits form a byte
        if bits >= 8
          bits -= 8
          rv.setbyte(index, (value >> bits) & 0xff)
          index += 1
        end
      end

      # Trailing bits of a final partial group must be zero, or the same bytes
      # would have more than one encoding.
      if bits > 0 && value.anybits?((1 << bits) - 1)
        raise TypeError, 'Non-canonical base64url input'
      end

      return rv
    end

    # Encodes the passed string into base64url encoding of its UTF-8 bytes.
    #
    # Any well-formed string is encodable (emojis, non-latin scripts, etc.). Raises a TypeError
    # on an ill-formed string, the counterpart of an unpaired surrogate — a surrogate code point has no UTF-8 encoding,
    # and an ill-formed String no byte encoding to publish. Unreachable through
    # the protocol surface: every internal call site encodes JSON.generate output, which
    # is always well-formed.
    #
    # @param s [String] A string to encode.
    #
    # @return [String] encoded string.
    def self.string_to_base64url(s)
      return array_buffer_to_base64url(string_to_utf8_bytes(s))
    end

    # Decodes the passed base64url encoded string, interpreting the decoded bytes as UTF-8.
    #
    # Raises a TypeError on malformed base64url input and on bytes that are not well-formed
    # UTF-8. A leading byte-order mark is preserved, not stripped: U+FEFF stays byte-visible,
    # so every byte sequence has exactly one decoded spelling.
    #
    # @param s [String] A string to decode.
    #
    # @return [String] decoded string.
    def self.base64url_to_string(s)
      return utf8_bytes_to_string(base64url_to_uint8(s))
    end

    # Encodes the passed string into its UTF-8 bytes.
    #
    # Raises a TypeError on an ill-formed string, the counterpart of an unpaired surrogate — a surrogate code point has no
    # UTF-8 encoding, and substituting U+FFFD would let two distinct strings share one byte encoding (the
    # platform's transcoders substitute, so the well-formedness gate lives here).
    #
    # @param s [String] A string to encode. Anything else raises.
    #
    # @return [String] the UTF-8 bytes of the string (a binary String).
    #
    # @raise [TypeError] when the value is not a string, or the string is ill-formed.
    def self.string_to_utf8_bytes(s)
      # an ill-formed String is "not a string" (`is_well_formed_string` is the encoding-validity test of `is_string`): the
      # `Unpaired surrogate` TypeError has no separate counterpart
      if !Helpers.is_well_formed_string(s)
        raise TypeError, 'stringToUtf8Bytes expects a string'
      end

      return s.b
    end

    # Decodes the passed UTF-8 bytes into a string.
    #
    # Strict: raises a TypeError on any ill-formed sequence — overlong encodings, encoded
    # surrogates, code points above U+10FFFF, truncated or stray continuation bytes. A leading
    # byte-order mark is preserved, not stripped.
    #
    # Backed by the runtime's encoding validity check (`String#valid_encoding?`). The strict-decode contract itself is
    # pinned by the conformance vectors, so ports use their own stdlib's strict decoder.
    #
    # @param bytes [String] The UTF-8 bytes to decode (a binary String). Anything else raises.
    #
    # @return [String] the decoded string.
    #
    # @raise [TypeError] when the value is not a String, or the bytes are not well-formed UTF-8.
    def self.utf8_bytes_to_string(bytes)
      if !bytes.is_a?(String)
        raise TypeError, 'utf8BytesToString expects a Uint8Array'
      end

      str = bytes.dup.force_encoding(Encoding::UTF_8)
      if !str.valid_encoding?
        raise TypeError, 'Ill-formed UTF-8 bytes'
      end

      return str
    end

    # Lowercases only the ASCII letters `A`-`Z` of the passed string, applying no other case mapping.
    #
    # Wire values that are "lowercased" before an ASCII grammar must use this instead of
    # String#downcase: the full Unicode case mapping would fold characters such as
    # U+212A KELVIN SIGN into ASCII (`k`), silently widening the wire alphabet in a way
    # other implementations (ASCII tolower) would not reproduce.
    #
    # @param string [String] A string to map.
    #
    # @return [String] the string with `A`-`Z` mapped to `a`-`z` and every other character intact.
    def self.ascii_lowercase(string)
      return string.tr('A-Z', 'a-z')
    end

    # Percent-decodes the passed string into utf-8.
    #
    # @param string [String] A string to decode.
    #
    # @return [String, nil] the decoded string, or nil when an escape is malformed (a `%` not
    #         followed by two hexadecimal digits) or decodes to ill-formed UTF-8.
    def self.percent_decode(string)
      # the port of `decodeURIComponent`: a `%XX` escape is its byte, every other character is copied through
      # (`+` included) and the result must be well-formed UTF-8; a value that is not a string has no decoding here
      if !Helpers.is_string(string)
        return nil
      end

      # Reject malformed percent escapes.
      if /%(?![0-9A-Fa-f]{2})/.match?(string)
        return nil
      end

      decoded = string.b.gsub(/%([0-9A-Fa-f]{2})/) { Regexp.last_match(1).hex.chr }
      decoded.force_encoding(Encoding::UTF_8)
      return decoded.valid_encoding? ? decoded : nil
    end

    # Checks that the passed string carries no surrogate code point (U+D800 to U+DFFF), so that it has a UTF-8 encoding.
    #
    # Every string takes this check before it is encoded, and every string parsed from JSON text is held to
    # the same rule: the `\uXXXX` escape of a surrogate is the one spelling of such a string that passes the
    # strict UTF-8 decoder, because the JSON text itself is plain ASCII. The name mirrors the ES2024
    # `String.prototype.isWellFormed`, which performs the same test.
    #
    # This is the Ruby form of the reference test: a Ruby String cannot hold a surrogate code point, so "carries no
    # surrogate code point, so it has a UTF-8 encoding" is the encoding test of {Triauth::Helpers.is_string} (valid UTF-8,
    # or ASCII-only in another ASCII-compatible encoding) applied to a value that is a String; an ill-formed String (an
    # encoded surrogate included) is the counterpart of a JS string that carries one.
    #
    # @param string [String] A string to check.
    #
    # @return [Boolean] true if the value is a string without surrogate code points, false otherwise.
    def self.is_well_formed_string(string)
      # `typeof string === 'string'` is `is_a?(String)` here, and `!UNPAIRED_SURROGATE_REGEXP.test(string)` is the
      # encoding validity of `is_string`
      return string.is_a?(String) && Helpers.is_string(string)
    end

    # Checks that the passed string does not contain fancy utf-8 characters such as emojis, right-to-left encoding, etc.
    #
    # This is useful in validation of user-provided identifiers and/or other strings that may be displayed in the UI.
    #
    # @param string [String] A string to check.
    # @param bytesize_limit [Integer, nil] The size limit for the string (counted in bytes). nil for unbound. Defaults to 255.
    #
    # @return [Boolean] true if string contains only 'normal' characters, false otherwise.
    def self.is_normal_string(string, bytesize_limit = 255)
      # Ensure that we are dealing with a string
      if !Helpers.is_string(string)
        return false
      end

      # If bytesizeLimit is set, enforce it
      if !bytesize_limit.nil? && bytesize_limit != 0 && byte_size(string) > bytesize_limit
        return false
      end

      return NORMAL_STRING_REGEXP.match?(string)
    end

    # Checks whether any label of the given hostname (or domain name) is in Punycode form.
    #
    # Punycode/IDN labels [RFC 3492] are blocked throughout the protocol, in identifiers, URLs,
    # and endpoint hosts alike, to keep look-alike "homograph" domains out of everything a user
    # may be shown.
    #
    # @param string [String] A hostname or domain name to check.
    #
    # @return [Boolean] true if the string carries an `xn--` label, false otherwise.
    def self.has_punycode_label(string)
      return Helpers.is_string(string) && XN_LABEL_REGEXP.match?(string)
    end

    # Parses an absolute http(s) URL given in its canonical spelling, and returns its components.
    #
    # This is a small subset of RFC 3986 admitting exactly one spelling per resource.
    # Owning it makes the accepted set identical on every engine (cross-engine URL parser
    # differentials are a classic source of origin confusion).
    #
    # The grammar:
    #   - scheme: the literal `https://` or `http://`,
    #   - host: dot-separated lowercase LDH labels (letters/digits/hyphens, 1–63 chars, no
    #     leading/trailing hyphen, no empty labels) whose final label is not numeric (all digits,
    #     or `0x` + hex digits) — or a canonical dotted-quad IPv4 literal (four decimal octets
    #     0–255, no leading zeros). Every other IPv4 spelling (hex, octal, dword, short forms)
    #     matches neither production; `[` is not in the grammar, so IPv6 literals are out as well,
    #   - port: optional; 1–65535 with no leading zeros, never the scheme's default,
    #   - userinfo: none (`@` cannot appear before the path),
    #   - path: required and absolute; characters from the RFC 3986 `pchar` set plus `/` and `%`
    #     (`|` is not an RFC 3986 URL character and never appears); no `.`/`..` segments in any
    #     spelling (`%2e` forms included),
    #   - query and fragment: optional and non-empty, over the path characters plus `?`.
    #
    # `%` is a plain character at this layer; the policy wrapper below rejects malformed escapes
    # before parsing. This parser is reachable only through that wrapper, so grammar and policy
    # always travel together.
    #
    # @param string [String] The URL string to parse.
    #
    # @return [Hash{Symbol => Object}, nil] The URL's components (a frozen Hash with the keys `scheme`, `host`, `port`,
    #   `path`, `query`, `fragment`, `origin`, `base`), or nil when the string is not a canonical URL. `port` is `''` and
    #   `query`/`fragment` are nil when absent; `origin` carries no trailing slash; `base` is the
    #   origin plus the path up to and including its last `/`.
    def self.parse_canonical_url(string)
      if !Helpers.is_string(string)
        return nil
      end

      # Scheme — the lowercase spelling only
      scheme = nil
      if string.start_with?('https://')
        scheme = 'https'
      elsif string.start_with?('http://')
        scheme = 'http'
      else
        return nil
      end

      tail = string[(scheme.length + 3)..]

      # The authority runs up to the first '/', '?' or '#'
      authority_end = tail.index(%r{[/?#]})
      authority = authority_end.nil? ? tail : tail[0...authority_end]
      tail = authority_end.nil? ? '' : tail[authority_end..]

      if authority == '' || authority.include?('@')
        return nil
      end

      # Optional port
      host = authority
      port = ''
      port_at = authority.rindex(':')
      if !port_at.nil?
        port = authority[(port_at + 1)..]
        host = authority[0...port_at]
        if !/\A[1-9][0-9]{0,4}\z/.match?(port) || # 1-65535: no leading zeros, and port 0 is not a destination
           port.to_i > 65_535 ||
           port == (scheme == 'https' ? '443' : '80') # an explicit default port is not canonical
          return nil
        end
      end

      # Host — a named host (LDH labels, non-numeric final label) or a canonical dotted-quad
      # IPv4 literal; every exotic IPv4 spelling matches neither production
      labels = host.empty? ? [''] : host.split('.', -1) # JS `''.split('.')` is `['']`
      if !URL_IPV4_QUAD_REGEXP.match?(host) &&
         (
           !labels.all? { |label| URL_HOST_LABEL_REGEXP.match?(label) } ||
           URL_NUMERIC_LABEL_REGEXP.match?(labels[-1])
         )
        return nil
      end

      # Fragment and query — split off in that order, so neither can hide in the other
      fragment = nil
      fragment_at = tail.index('#')
      if !fragment_at.nil?
        fragment = tail[(fragment_at + 1)..]
        tail = tail[0...fragment_at]
        if !URL_QUERY_REGEXP.match?(fragment)
          return nil
        end
      end

      query = nil
      query_at = tail.index('?')
      if !query_at.nil?
        query = tail[(query_at + 1)..]
        tail = tail[0...query_at]
        if !URL_QUERY_REGEXP.match?(query)
          return nil
        end
      end

      # Path — what remains
      path = tail
      if path[0] != '/' ||
         !URL_PATH_REGEXP.match?(path) ||
         path.split('/', -1).any? { |segment| URL_DOT_SEGMENT_REGEXP.match?(segment) }
        return nil
      end

      origin = "#{scheme}://#{host}#{":#{port}" unless port.empty?}"
      base = origin + path[0, path.rindex('/') + 1]

      return { scheme: scheme, host: host, port: port, path: path, query: query, fragment: fragment, origin: origin, base: base }.freeze
    end
    private_class_method :parse_canonical_url

    # Checks that the passed string is a canonical, safe-to-display URL.
    #
    # A string passes only when it is:
    #   - non-empty and within `LIMITS[:urlBytesize]`,
    #   - printable ASCII only (no spaces or control characters),
    #   - free of malformed `%`-escapes (every `%` is followed by two hex digits),
    #   - a canonical `http` or `https` URL per the closed grammar (a lowercase LDH host with a
    #     non-numeric final label, or a canonical dotted-quad IPv4 literal — no other IP spelling,
    #     no IPv6; optional non-default port; absolute path; optional query and fragment; no
    #     userinfo; the RFC 3986 `pchar` charset, which has no `|`; no `.`/`..`/`%2e` path
    #     segments), and
    #   - free of Punycode/IDN `xn--` labels (homograph look-alikes).
    #
    # Used to validate caller-supplied URLs that are later embedded in signatures or shown to the
    # user: the `callbackUrl` (whose base-URL span carries the extra `;` rule at the validator) and
    # attachment `sourceUrl`s. URLs that act as verbatim trust anchors — attestation provider URLs —
    # use the narrower {Triauth::Helpers.is_secure_url} instead.
    #
    # @param string [String] A string to check.
    #
    # @return [Boolean] true if the string is a canonical URL meeting all the above constraints, false otherwise.
    def self.is_canonical_url(string)
      return !canonical_url(string).nil?
    end

    # Checks that the passed string is a canonical URL (see {Triauth::Helpers.is_canonical_url})
    # on a secure origin: an `https` URL with a named (non-IP-literal) host — or, for local
    # development, an `http` URL on the literal host `localhost`.
    #
    # This is the acceptance rule for URLs used verbatim as trust anchors: attestation provider
    # URLs, which are displayed to the user as the trust decision and embedded whole as the
    # attestation Segment's `via`. Callback URLs take the wider {Triauth::Helpers.is_canonical_url}
    # instead — only their base URL enters the envelope, under its own delimiter rule.
    #
    # Every string this accepts is also accepted by `is_canonical_url`: both are views over the same
    # parse, so the two accept-sets cannot diverge.
    #
    # @param string [String] A string to check.
    #
    # @return [Boolean] true if the string is a canonical URL on a secure origin, false otherwise.
    def self.is_secure_url(string)
      url = canonical_url(string)

      return !url.nil? &&
             !URL_IPV4_QUAD_REGEXP.match?(url[:host]) &&
             (url[:scheme] == 'https' || url[:host] == 'localhost')
    end

    # The single accept-set behind every canonical-URL helper: the closed grammar of
    # `parse_canonical_url` plus the protocol policy — size cap, printable
    # ASCII, well-formed `%`-escapes, and no Punycode label.
    #
    # `is_canonical_url`, `is_secure_url`, `get_base_url`, and `url_host` are all views over this one
    # function (`is_secure_url` a narrowing one), so no URL can ever pass one of them while failing
    # another's underlying parse.
    #
    # @param string [String] A string to check and parse.
    #
    # @return [Hash{Symbol => Object}, nil] The parsed components (see `parse_canonical_url`),
    #   or nil when the string is not a canonical URL under the full protocol rules.
    def self.canonical_url(string)
      # Ensure that we are dealing with a string
      if !Helpers.is_string(string)
        return nil
      end

      # Ensure size limits
      if string.length == 0 || byte_size(string) > Protocol::LIMITS[:urlBytesize]
        return nil
      end

      # ASCII only
      if !/\A[\x21-\x7E]+\z/.match?(string)
        return nil
      end

      # Reject malformed percent escapes.
      if /%(?![0-9A-Fa-f]{2})/.match?(string)
        return nil
      end

      # The string must be a canonical URL per the closed grammar
      url = parse_canonical_url(string)
      if url.nil?
        return nil
      end

      # Block Punycode/IDN homographs (RFC 3492)
      if has_punycode_label(url[:host])
        return nil
      end

      return url
    end
    private_class_method :canonical_url

    # Checks that the passed string uses only characters from base64URL alphabet.
    #
    # This method is intended for quick validation and is not bullet-proof - e.g., may not check that the string is properly base64URL encoded.
    #
    # @param string [String] A string to check.
    #
    # @return [Boolean] true if string contains only base64url characters, false otherwise.
    def self.is_base64url_string(string)
      return Helpers.is_string(string) && BASE64URL_REGEXP.match?(string)
    end

    # Checks that the passed string is a valid domain name.
    #
    # Accepts case-insensitive LDH domain names of at least two labels. Labels in Punycode form
    # (`xn--`) are rejected (homograph look-alikes), and so is a numeric final label (all digits,
    # or `0x` + hex digits) — real TLDs are never numeric, and this keeps every IPv4 spelling,
    # exotic notations included, from ever being taken for a domain name.
    #
    # This method is intended for quick validation and is not bullet-proof - e.g., exotic domain names may not be recognized
    #
    # @param string [String] A string to check.
    #
    # @return [Boolean] true if string is a domain name, false otherwise.
    def self.is_domain_name(string)
      return Helpers.is_string(string) &&
             byte_size(string) <= Protocol::LIMITS[:domainNameBytesize] &&
             DOMAIN_NAME_REGEXP.match?(string) &&
             !has_punycode_label(string) &&
             !URL_NUMERIC_LABEL_REGEXP.match?(string[(string.rindex('.') + 1)..])
    end

    # Returns the base URL of the given canonical URL string: its origin plus the path up to and
    # including the last `/`, with query and fragment removed.
    #
    # For example, `https://example.com/foo/bar` returns `https://example.com/foo/`, while
    # `https://example.com/foo/` returns `https://example.com/foo/` unchanged.
    #
    # The base URL is what the authenticator signs into the `via` field of a signature envelope,
    # so this accepts only canonical URLs (see {Triauth::Helpers.is_canonical_url}) — for
    # anything else it returns `false` rather than a normalized guess.
    #
    # @param url [String] A canonical URL string to process.
    #
    # @return [String, false] The base URL with a trailing slash, or `false` if the input is not a canonical URL.
    def self.get_base_url(url)
      parsed = canonical_url(url)
      return parsed.nil? ? false : parsed[:base]
    end

    # Returns the host (without the port) of the given canonical URL string.
    #
    # @param url [String] A canonical URL string to process.
    #
    # @return [String, false] The lowercase hostname, or `false` if the input is not a canonical URL.
    def self.url_host(url)
      parsed = canonical_url(url)
      return parsed.nil? ? false : parsed[:host]
    end

    # Calculates the SHA-256 digest of the passed string.
    #
    # @param message [String] A message whose SHA-256 digest should be calculated.
    # @return [String] the sha256 of the given message (base64url).
    def self.sha256(message)
      data = string_to_utf8_bytes(message)

      hash = OpenSSL::Digest::SHA256.digest(data)
      return array_buffer_to_base64url(hash)
    end

    # Computes the HMAC-SHA-256 of a message under a key.
    #
    # Keys the private-mode identity-domain derivation (`Triauth::IdentityDomain.derive_full_label`).
    #
    # @param key [String] The key bytes (a binary String).
    # @param message [String] The message bytes (a binary String).
    # @return [String] the 32-byte MAC (a binary String).
    def self.hmac_sha256(key, message)
      return OpenSSL::HMAC.digest('SHA256', key, message)
    end

    # Returns a P-256 public key as the 65-byte uncompressed point (`0x04`, x, y), the form that the Web Crypto
    # `raw` import accepts on all runtimes, and the form that `Verifiers::Base.import_key` accepts.
    #
    # Accepts the uncompressed point (65 bytes, prefix `0x04`) and returns it unchanged. Accepts the compressed
    # point (33 bytes, prefix `0x02` or `0x03`, then x) and decodes it here, because not all Web Crypto
    # implementations import a compressed point. Rejects all other forms, the hybrid form (prefix `0x06` or `0x07`)
    # included, also on runtimes whose Web Crypto import accepts them. The result is therefore the same on all runtimes.
    #
    # @param bytes [String] The public key bytes (a binary String).
    # @return [String] the 65-byte uncompressed point (a binary String).
    #
    # @raise [TypeError] when the bytes are not an uncompressed or a compressed point, or when the compressed point
    #                    is not on the curve.
    def self.decode_p256_public_key(bytes)
      if bytes.bytesize == 65 && bytes.getbyte(0) == 0x04
        return bytes
      end

      if bytes.bytesize != 33 || (bytes.getbyte(0) != 0x02 && bytes.getbyte(0) != 0x03)
        raise TypeError, 'Invalid public key'
      end

      # x must be smaller than p, so that a key has one compressed form only
      p = P256_P
      x = bytes.byteslice(1, 32).unpack1('H*').to_i(16)
      if x >= p
        raise TypeError, 'Invalid public key'
      end

      # The square root of y² = x³ - 3x + b (mod p), the on-curve check and the parity of y are OpenSSL's: `EC_POINT_bn2point` decompresses the point and validates it
      begin
        point = OpenSSL::PKey::EC::Point.new(OpenSSL::PKey::EC::Group.new('prime256v1'), OpenSSL::BN.new(bytes, 2))
      rescue OpenSSL::PKey::EC::Point::Error
        raise TypeError, 'Invalid public key'
      end
      return point.to_octet_string(:uncompressed)
    end

    # `#modPow` (square-and-multiply) has no counterpart: the exponentiation is OpenSSL's (`decode_p256_public_key`)

    # Generates a random string of the given length using the base64 url alphabet.
    #
    # The underlying byte source is the effective config's `randomSource` when set, otherwise
    # `SecureRandom.random_bytes`. See `Triauth.config[:randomSource]` for details on overriding
    # the entropy source.
    #
    # @param len [Integer] The character length of the returned string.
    # @param config [Hash] The effective config whose `randomSource` supplies the bytes;
    #                      defaults to the global `Triauth.config`.
    # @return [String] a random string of the given length
    def self.random_string(len, config = Triauth.config)
      # base64url packs 3 random bytes into 4 chars (0.75 bytes/char), so `len` chars need
      # ceil(len * 0.75) bytes; the +1 covers the partial final group and guarantees the encoded
      # string is at least `len` chars before the substring trim. Every returned char is therefore
      # backed by fresh random bytes (no padding/repetition is introduced by the trim).
      n = (len * 0.75).ceil + 1
      random_source = config[:randomSource]
      source = random_source || ->(count) { SecureRandom.random_bytes(count) }
      bytes = source.call(n)
      if !bytes.is_a?(String) || bytes.bytesize != n
        raise ArgumentError, "randomSource must return #{n} bytes"
      end

      return array_buffer_to_base64url(bytes.b)[0, len]
    end

    # Verifies that the passed object has only properties that are on the passed whitelist.
    #
    # This method helps to ensure that the user-passed arguments were not misspelled or come from untrusted sources.
    # It also helps to recognize that an argument was passed from the user in the subsequent code, by enforcing (in strict
    # mode) that only non-undefined values may be set by the user.
    #
    # @param obj [Hash] An object which properties should be checked.
    # @param whitelist [Array<Symbol>] An array of allowed properties (whitelist).
    # @param strict [Boolean] When true (default), a whitelisted key whose value is `undefined` is rejected; use this at
    #   trust boundaries (user-facing options/constraints) to force callers to omit a value rather than pass `undefined`.
    #   Ruby has no `undefined`: a `nil` value passes, as `null` does in triauth-js.
    #
    # @return [Boolean] true if object contains only properties from the whitelist, false otherwise
    def self.has_only_known_properties(obj, whitelist, strict = true) # rubocop:disable Lint/UnusedMethodArgument -- the `strict` check of an `undefined` value has no counterpart: Ruby has one null, which follows the JS `null` branch
      if !obj.is_a?(Hash)
        return false
      end

      obj_keys = obj.keys
      return obj_keys.all? { |key| whitelist.include?(key) }
    end

    # Returns the number of bytes it takes to store the given string in UTF-8.
    #
    # This method is helpful when validating untrusted input, as simply checking .length
    # may be not enough for utf-8 encoded strings.
    #
    # @param str [String] A string for which its underlying bytesize should be calculated.
    #
    # @return [Integer] The number of bytes.
    def self.byte_size(str)
      return str.bytesize
    end

    # Parses the provided JSON text and returns the object it encodes.
    #
    # The native JSON parser reads the text, then one walk over the parsed value applies the rules below, so that
    # a value which passes them reads the same in every language:
    #   - the source is a string of at most 256KB, and its root is an object,
    #   - a number is a whole number of magnitude at most 2^53 - 1 (`Number.isSafeInteger`), the range that every
    #     JSON parser reads exactly: `1.0` and `1e2` are the whole numbers 1 and 100, while a fraction, a larger
    #     integer or a literal that overflows to Infinity is rejected,
    #   - a string carries no surrogate code point (the JSON escape of a surrogate is the one spelling of such a
    #     string that passes the strict UTF-8 decoder),
    #   - a member name is ASCII, at most 255 characters long, and never `__proto__`, `constructor` or `prototype`,
    #   - objects and arrays nest at most 8 levels deep: the root object is level 1, and other values add no level.
    #
    # A member name that occurs twice in one object keeps its last value, as the native parser reads it, and the
    # rules apply to that last value.
    #
    # @param source [String] A source string that contains json encoded data.
    #
    # @return [Hash{Symbol => Object}] deserialized object (keys are Symbols)
    def self.safe_parse_json(source)
      err = RuntimeError.new('JSON validation error')

      # Pre-validate that source is a string not larger than 256KB
      if !Helpers.is_string(source) ||
         Helpers.byte_size(source) > Protocol::LIMITS[:jsonMaxBytesize]
        raise err
      end

      # The json gem admits comments and unknown escapes that the JS parser rejects, and cannot parse a surrogate escape
      # outside a pair into the surrogate code point that the string-value rule of the walk below refuses in JS (see
      # `JSON_STRICT_SOURCE_REGEXP`): the same inputs are a parser failure here
      if !JSON_STRICT_SOURCE_REGEXP.match?(source)
        raise JSON::ParserError, 'source is not strict JSON (a comment, an unknown escape or a surrogate escape outside a pair)'
      end

      json_object = JSON.parse(source, symbolize_names: true)

      # We always expect to see JSON encoded objects ({}) at root level.
      if !json_object.is_a?(Hash)
        raise err
      end

      if !is_bounded_json_value(json_object, 1)
        raise err
      end

      return json_object
    end

    # Checks one value produced by `JSON.parse`, and every value inside it, against the rules of `Helpers.safe_parse_json`.
    #
    # The walk goes at most one level past the nesting limit, so its recursion depth stays bounded whatever the parser built.
    #
    # @param value [Object] A value produced by `JSON.parse`.
    # @param depth [Integer] The nesting level of the value if it is an object or an array (the root object is level 1).
    #
    # @return [Boolean] true if the value and every value inside it follow the rules, false otherwise.
    def self.is_bounded_json_value(value, depth)
      if Helpers.is_number(value)
        return Helpers.is_safe_integer(value)
      end

      if value.is_a?(String) # `typeof === 'string'` is `is_a?(String)` here so that the well-formedness test is the deciding one
        return Helpers.is_well_formed_string(value)
      end

      # true, false and null add no nesting level
      if !(value.is_a?(Hash) || value.is_a?(Array))
        return true
      end

      if depth > Protocol::LIMITS[:jsonMaxNestingDepth]
        return false
      end

      if value.is_a?(Array)
        return value.each_index.all? do |i|
          # JS has one number type (language-hazards B3): an integral Float the parser produced from a spelling
          # such as `1.0` or `1e2` is the number 1 or 100 there, so it becomes the Integer here (a safe integer)
          value[i] = value[i].to_i if value[i].is_a?(Float) && Helpers.is_safe_integer(value[i])
          is_bounded_json_value(value[i], depth + 1)
        end
      end

      return value.keys.all? do |name|
        # JS has one number type (language-hazards B3): an integral Float the parser produced from a spelling
        # such as `1.0` or `1e2` is the number 1 or 100 there, so it becomes the Integer here (a safe integer)
        value[name] = value[name].to_i if value[name].is_a?(Float) && Helpers.is_safe_integer(value[name])
        name.to_s.length <= Protocol::LIMITS[:jsonMaxKeyLength] &&
        !/[^\x00-\x7F]/.match?(name.to_s) &&
        !PROTOTYPE_NAMES.include?(name.to_s) &&
        is_bounded_json_value(value[name], depth + 1)
      end
    end
    private_class_method :is_bounded_json_value

    # Builds a minimal in-memory LRU cache - the default answer store of `Triauth::Resolvers::CachingResolver`.
    #
    # The returned object's `get` and `set` methods are plain synchronous calls here (they return Promises in
    # triauth-js) so a caller can swap in a custom remote cache without changing the call sites.
    #
    # @param size [Integer] Maximum number of entries. Defaults to 1024.
    #
    # @return [LRUCache] An LRU cache exposing `get(key)`, `set(key, value)`, and `resize(new_size)`.
    def self.create_lru_cache(size = 1024)
      return LRUCache.new(size)
    end

    # The port of the closure object that `create_lru_cache` returns: an LRU cache over an insertion-ordered Hash
    # (`cache.keys.first` is the oldest entry). Keys are Strings.
    class LRUCache
      # @param size [Integer] Maximum number of entries.
      def initialize(size)
        @size = size
        @cache = {}
      end

      # @param key [String] The entry's key.
      #
      # @return [Object, nil] the cached value, now the most recently used, or nil when absent.
      def get(key)
        return nil if !@cache.key?(key)

        val = @cache[key]
        @cache.delete(key)
        @cache[key] = val
        return val
      end

      # @param key [String] The entry's key.
      # @param val [Object] The value to store; the oldest entry is evicted when the cache is full.
      #
      # @return [void]
      def set(key, val)
        if @cache.key?(key)
          @cache.delete(key)
        elsif @cache.size >= @size
          @cache.delete(@cache.keys.first)
        end
        @cache[key] = val
      end

      # @param new_size [Integer] The new maximum number of entries; the oldest entries beyond it are evicted.
      #
      # @return [void]
      def resize(new_size)
        @size = new_size
        @cache.delete(@cache.keys.first) while @cache.size > @size
      end
    end

    # Checks whether the given value is a well-formed lookup code - the 16-character token that
    # addresses an identity's records in the DNS when resolving in private mode.
    #
    # @param val [Object] A value to check; anything that is not a string is reported as not a lookup code.
    #
    # @return [Boolean] true when the value is a string of exactly 16 uppercase letters and digits
    def self.is_lookup_code(val)
      return Helpers.is_string(val) && LOOKUP_CODE_REGEXP.match?(val)
    end

    # Returns the effective settings for one call or instance: the global `Triauth.config`
    # with the given per-call overrides merged over it. The global Hash is read at call
    # time, so runtime mutations of `Triauth.config` are picked up.
    #
    # @param overrides [Hash] Per-call overrides for the global Triauth.config settings. Defaults to `{}`.
    #
    # @return [Hash{Symbol => Object}] the merged settings (a new Hash)
    def self.merge_config(overrides = {})
      return Helpers.object_assign({}, Triauth.config, overrides)
    end

    # Helpers with no triauth-js counterpart (the profile's idiom table).

    # The JS `\s` set (ECMA-262 WhiteSpace and LineTerminator), as a character class fragment for interpolation into
    # regexes (`/#{JS_WS}+/`); `String#strip` is never used.
    JS_WS = '[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]'
    # Its complement, the JS `\S`.
    JS_NOT_WS = '[^\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]'
    # The JS `.`: every character but the four line terminators `\n`, `\r`, U+2028 and U+2029.
    JS_DOT = '[^\n\r\u2028\u2029]'
    JS_WS_LEADING_REGEXP = /\A#{JS_WS}+/
    JS_WS_TRAILING_REGEXP = /#{JS_WS}+\z/
    private_constant :JS_WS_LEADING_REGEXP, :JS_WS_TRAILING_REGEXP

    # The port of the optional call `config.logger?.<level>?.(...)`: calls `config[:logger].public_send(level, *args)`
    # only when `config[:logger]` is non-nil and responds to `level`; returns nil otherwise. The remaining
    # arguments are the values to log, passed through verbatim.
    #
    # @param config [Hash] Effective per-call config; only `config[:logger]` is consulted here.
    # @param level [Symbol] One of `:debug`, `:info`, `:warn`, `:error`.
    #
    # @return [Object, nil] whatever the logger's method returns, or nil when it was not called.
    def self.log(config, level, *)
      logger = config[:logger]
      return nil if logger.nil? || !logger.respond_to?(level)

      return logger.public_send(level, *)
    end

    # The port of `Date.now()`: the wall clock in integer milliseconds. The JSON runner and the time-sensitive
    # tests freeze it by redefining this singleton method; `now` (monotonic, durations only) is never frozen.
    #
    # @return [Integer] milliseconds since the Unix epoch.
    def self.date_now
      return Process.clock_gettime(Process::CLOCK_REALTIME, :millisecond)
    end

    # The port of `typeof x === 'string'`: a String that is valid UTF-8, or ASCII-only in another ASCII-compatible
    # encoding. An ill-formed String is not a string (the counterpart of a JS string with an unpaired surrogate failing
    # its regex gate), which also makes every regex match on a value that passed this check safe.
    #
    # @param x [Object] A value to check.
    #
    # @return [Boolean] true for a well-formed String, false otherwise.
    def self.is_string(x)
      return x.is_a?(String) && (x.encoding == Encoding::UTF_8 ? x.valid_encoding? : x.ascii_only?)
    end

    # The port of `typeof x === 'number'`: an Integer or a Float (`Float::NAN` and `Float::INFINITY` included;
    # `true` and `false` are not numbers).
    #
    # @param x [Object] A value to check.
    #
    # @return [Boolean] true for an Integer or a Float, false otherwise.
    def self.is_number(x)
      return x.is_a?(Integer) || x.is_a?(Float)
    end

    # The port of `Number.isInteger(x)`: an Integer, or a finite Float with no fractional part (`30.0` is an integer,
    # as it is in JS).
    #
    # @param x [Object] A value to check.
    #
    # @return [Boolean] true for an integral number, false otherwise.
    def self.is_integer(x)
      return x.is_a?(Integer) || (x.is_a?(Float) && x.finite? && x == x.floor)
    end

    # The port of `Number.isSafeInteger(x)`: an Integer, or a finite integral Float, of magnitude at most 2^53 - 1
    # (`true` and `false` are not Integers; `Float::NAN` and `Float::INFINITY` fail `is_integer`).
    #
    # @param x [Object] A value to check.
    #
    # @return [Boolean] true for a safe integer, false otherwise.
    def self.is_safe_integer(x)
      return Helpers.is_integer(x) && x.abs <= (2**53) - 1
    end

    # The port of the JS object key order (`Object.entries`, `Object.keys`, `for..in`) for a Hash whose keys may be
    # array indexes: the canonical array-index keys (`:"0"`, `:"1"`, ... up to 2**32 - 2) come first in ascending
    # numeric order, then the remaining keys in insertion order.
    #
    # @param hash [Hash{Symbol => Object}] The Hash to list.
    #
    # @return [Array<Array(Symbol, Object)>] the `[key, value]` pairs in JS order.
    def self.ordered_entries(hash)
      index_keys = []
      other_keys = []
      hash.each_key do |key|
        if /\A(0|[1-9][0-9]*)\z/.match?(key.to_s) && key.to_s.to_i <= (2**32) - 2
          index_keys.push(key)
        else
          other_keys.push(key)
        end
      end
      index_keys.sort_by! { |key| key.to_s.to_i }
      return (index_keys + other_keys).map { |key| [key, hash[key]] }
    end

    # The port of `Object.assign({}, ...sources)` for sources that may be any caller value: a Hash is merged (a nil
    # value still overrides, as `undefined` does); nil, true, false, numbers and Symbols contribute nothing; a String
    # or an Array contributes its characters or elements under the keys `:"0"`, `:"1"`, ... (JS spreads array-likes),
    # so the known-keys guards reject a stray String or Array exactly as triauth-js does; any other object contributes
    # nothing.
    #
    # @param sources [Array<Object>] The sources, merged left to right into a new Hash.
    #
    # @return [Hash{Symbol => Object}] a new Hash.
    def self.object_assign(*sources)
      target = {}
      sources.each do |source|
        case source
        when Hash
          target.merge!(source)
        when String
          source.each_char.with_index { |char, i| target[i.to_s.to_sym] = char }
        when Array
          source.each_with_index { |element, i| target[i.to_s.to_sym] = element }
        end
      end
      return target
    end

    # The port of `String.prototype.trim`: strips the JS whitespace set ({JS_WS}) from both ends; NUL is kept.
    #
    # @param s [String] A string to trim.
    #
    # @return [String] the trimmed string.
    def self.trim(s)
      return s.sub(JS_WS_LEADING_REGEXP, '').sub(JS_WS_TRAILING_REGEXP, '')
    end

    # The port of `String.prototype.trimEnd`: strips the JS whitespace set ({JS_WS}) from the end; NUL is kept.
    #
    # @param s [String] A string to trim.
    #
    # @return [String] the trimmed string.
    def self.trim_end(s)
      return s.sub(JS_WS_TRAILING_REGEXP, '')
    end

    # The port of `encodeURIComponent`: the unreserved characters `A-Z a-z 0-9 - _ . ! ~ * ' ( )` are kept and every
    # other character is percent-encoded as the uppercase hex of its UTF-8 bytes.
    #
    # @param s [String] A string to encode.
    #
    # @return [String] the encoded string.
    #
    # @raise [TypeError] when the value is not a well-formed string (`encodeURIComponent` throws a `URIError` then).
    def self.encode_uri_component(s)
      if !Helpers.is_string(s)
        raise TypeError, 'encodeUriComponent expects a string'
      end

      return s.b.gsub(/[^A-Za-z0-9\-_.!~*'()]/) { |byte| format('%%%02X', byte.ord) }.force_encoding(Encoding::UTF_8)
    end

    # The port of `fetch(url, fetchOptions)` over one `Net::HTTP` per call: the default transport of the DNS-over-HTTPS
    # resolvers, and the contract an injected `options[:fetch]` must honor. `fetch.call(url, fetch_options) { |response| }`
    # sends a `GET` with `fetch_options[:headers]`, bounds the connect, the write and every read by
    # `fetch_options[:timeout]` milliseconds when given (Net::HTTP's 60 s defaults otherwise), yields a {FetchResponse}
    # inside the connection (so the body can stream) and returns the block's value. One request per call: Net::HTTP's own
    # retry of idempotent requests is off. TLS: an `https` URL verifies the peer certificate and the host name
    # (`OpenSSL::SSL::VERIFY_PEER`, never configurable off). Redirects are not followed (a 3xx answer has `ok` false).
    # The proxy environment (`http_proxy`, `https_proxy`, `no_proxy`) is honored, as `Net::HTTP.new` does by default.
    # Raising from inside the block closes the connection (the port of aborting a body read).
    #
    # @param url [String] The absolute http(s) URL to request.
    # @param fetch_options [Hash] `headers` (a `Hash{String => String}`, the request headers) and `timeout`
    #   (Integer milliseconds, nil for Net::HTTP's defaults). Defaults to `{}`.
    #
    # @yieldparam response [FetchResponse] the response, valid inside the block only.
    #
    # @return [Object] whatever the block returns.
    def self.fetch(url, fetch_options = {})
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.max_retries = 0
      if uri.scheme == 'https'
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end
      if !fetch_options[:timeout].nil?
        seconds = fetch_options[:timeout] / 1000.0
        http.open_timeout = seconds
        http.read_timeout = seconds
        http.write_timeout = seconds
      end
      request = Net::HTTP::Get.new(uri.request_uri, fetch_options[:headers] || {})
      http.start do
        http.request(request) do |res|
          return yield(FetchResponse.new(res))
        end
      end
    end

    # The response object that {Helpers.fetch} yields: a thin wrapper over `Net::HTTPResponse` with the contract every
    # transport must honor - `ok` (true for a 2xx status), `status` (Integer), `headers` (Hash of lowercase String
    # header names to String values) and `each_chunk { |bytes| }` (streams the body as binary String chunks; the port
    # of `body.getReader()`). It is valid inside the `fetch` block only.
    class FetchResponse
      # @param res [Net::HTTPResponse] The response, inside its connection block.
      def initialize(res)
        @res = res
      end

      # @return [Boolean] true for a 2xx status.
      def ok
        return @res.code.to_i >= 200 && @res.code.to_i < 300
      end

      # @return [Integer] the HTTP status code.
      def status
        return @res.code.to_i
      end

      # @return [Hash{String => String}] the response headers, names lowercased; several values of one name are joined with `, `.
      def headers
        return @res.each_header.to_h
      end

      # Streams the body as it arrives; may be called once.
      #
      # @yieldparam bytes [String] a chunk of the body (a binary String).
      #
      # @return [void]
      def each_chunk(&)
        @res.read_body(&)
      end
    end
  end
end
