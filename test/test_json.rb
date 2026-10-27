# frozen_string_literal: true

# Cross-language JSON-driven test runner.
#
# Each JSON suite describes deterministic input (DNS records, a fixed clock, an optional
# byte stream for randomness) and a list of API calls with strict-match expected results.
# The same fixtures are intended to be run against future ports of the library
# (Python, Go, ...) so protocol behavior stays uniform across implementations.
#
# Schema:
#   {
#     "title":       string,
#     "description": string,
#     "dnsEntries":  { "<domain>": null | { "<TYPE>": [string | {value, ttl, dnssec}, ...] } | { "_error": "<message>" } },
#     "currentTime": number,    // ms since epoch — suite-level default
#     "tests": [
#       {
#         "name":        string,
#         "call":        "<TriauthMethod>",
#         "args":        [...positional],
#         "currentTime": number,   // OPTIONAL — overrides the suite-level currentTime
#         "dnsEntries":  { ... },  // OPTIONAL — shallow-merged on top of the suite-level dnsEntries
#         "random":      "<lowercase hex>",   // OPTIONAL bytes consumed by randomSource
#         "expected":    {...}                // may be omitted in RECORD mode
#       }
#     ]
#   }
#
# Rules:
#   - dnsEntries[domain] === null is observationally equivalent to omitting the key
#     (both yield [] from the stub, matching real resolver NXDOMAIN behavior — see
#     src/resolvers/node_dns.js:82 and src/resolvers/dns_json.js:128). The null form is
#     kept as an expressive hint for readers.
#   - dnsEntries[domain] === { "_error": "..." } makes the stub reject that domain's DNS
#     query, simulating a SERVFAIL or network error. resolveConfig (src/resolvers/base.js)
#     catches the rejection and throws TriauthError(dns_unavailable), which propagates through the
#     resolve() catch blocks in AuthenticationEndpoint and IdentityDomain.
#   - Per-test dnsEntries is a per-domain shallow merge over the suite-level entries:
#     keys present in the test patch override completely (use null to "remove" / NXDOMAIN
#     a domain that was set at the suite level), keys absent inherit unchanged.
#   - Per-test currentTime, when set, overrides the suite-level value for that test only.
#     Time stays frozen for the entire test (no wall-clock progression).
#   - args is always an array (spread into the call). whois({identifier: "foo"}) → args: [{"identifier": "foo"}].
#   - random is a lowercase hex string of bytes. The runner installs a deterministic
#     Triauth.config.randomSource that returns these bytes in order; tests not consuming
#     randomness omit the field.
#   - expected is matched with assert.deepStrictEqual.
#   - A successful stage-1 result ({challenge, redirectUrl}) is masked before matching, because stage 1 mints a fresh
#     key pair for every challenge. The stored challenge is `<c>.<decryptionKey>`, and `<c>` carries `"ek":"<87 chars>"`.
#     The runner checks that a value sealed to `ek` opens with the decryption key, replaces the decryption key with
#     `DK`, base64url-decodes `<c>`, replaces the `ek` value with `EK` in the JSON text, and re-encodes it, in
#     `challenge` and in the `redirectUrl` fragment. When the fragment has `request=<nonce>.<ciphertext>`, the runner
#     checks that `skid` is the session key ID of the `sessionKey` argument (its key after any `<domain>:`), and that
#     the request opens under that key to `<c>`. Then it replaces the request with `REQUEST`. Ports apply the same rule.
#
# Record mode:
#   Run with RECORD=1 (e.g., `RECORD=1 npm run test:json`) to capture actual output and
#   rewrite the JSON file. Missing or mismatching expected blocks are filled/replaced.
#   Normal runs are read-only. Node-only (no fs in browser).
#
# Ruby notes (this port):
#   - The `expected` block and the fixtures are parsed with `symbolize_names: true` (every data key is a Symbol,
#     as in the library's results).
#   - Before comparing, both the result and `expected` pass through a deep normalization that removes Hash members
#     whose value is `nil`: triauth-js recorded `expected` through `JSON.stringify`, which drops `undefined`, and
#     Ruby has one null for both (the profile's drop-null rule). `assert_equal` is the port of `assert.deepStrictEqual`.
#   - RECORD mode has no counterpart: the fixtures are authored by the reference (triauth-js) only.
#   - `randomSource` is a callable that receives a byte count and returns a binary String of exactly that many bytes
#     (the Ruby contract), instead of filling an array in place.
#   - `JSON_SUITE=<file>.json` runs one suite (e.g., `JSON_SUITE=sign.json rake test:json`), as `ONLY` does.
#   - `maskStage1` is `mask_stage1` of `JsonSuiteRunner::Masking`, a module included into every suite's `describe`,
#     so that its assertions run as the spec's (a `module_function` cannot assert).

require_relative 'setup'
require_relative 'stubs/dns_resolver'
require 'json'

# The JSON `import`s: plain `JSON.parse` with Symbol keys (never `Helpers.safe_parse_json` - the fixtures exceed its size cap)
whois_suite    = JSON.parse(File.read(File.expand_path('fixtures/json/whois.json', __dir__)), symbolize_names: true)
auth_suite     = JSON.parse(File.read(File.expand_path('fixtures/json/auth.json', __dir__)), symbolize_names: true)
ping_suite     = JSON.parse(File.read(File.expand_path('fixtures/json/ping.json', __dir__)), symbolize_names: true)
check_suite    = JSON.parse(File.read(File.expand_path('fixtures/json/check.json', __dir__)), symbolize_names: true)
sign_suite     = JSON.parse(File.read(File.expand_path('fixtures/json/sign.json', __dir__)), symbolize_names: true)
stamp_suite    = JSON.parse(File.read(File.expand_path('fixtures/json/stamp.json', __dir__)), symbolize_names: true)
verify_suite   = JSON.parse(File.read(File.expand_path('fixtures/json/verify.json', __dir__)), symbolize_names: true)
attest_suite   = JSON.parse(File.read(File.expand_path('fixtures/json/attest.json', __dir__)), symbolize_names: true)
validate_suite = JSON.parse(File.read(File.expand_path('fixtures/json/validate.json', __dir__)), symbolize_names: true)

# `RECORDING` has no counterpart: there is no RECORD mode (the fixtures are authored by triauth-js)

# Optional single-suite filter (e.g., `JSON_SUITE=sign.json rake test:json`) used to run or
# measure coverage of one suite in isolation. Unset runs every suite.
only = ENV.fetch('JSON_SUITE', nil)

suites = [
  { file: 'whois.json', data: whois_suite },
  { file: 'auth.json',  data: auth_suite },
  { file: 'ping.json',  data: ping_suite },
  { file: 'check.json', data: check_suite },
  { file: 'sign.json',  data: sign_suite },
  { file: 'stamp.json', data: stamp_suite },
  { file: 'verify.json', data: verify_suite },
  { file: 'attest.json', data: attest_suite },
  { file: 'validate.json', data: validate_suite }
].select { |s| only.nil? || only == '' || s[:file] == only } # `!ONLY`: the JS falsy set of a string (nil and '')

# The per-suite `path` served RECORD mode only: dropped

# The file-scope functions of test_json.js (a module, not top-level `def`s).
module JsonSuiteRunner
  module_function

  def hex_to_bytes(hex)
    if !Triauth::Helpers.is_string(hex) || hex.length.odd? || !/\A[0-9a-f]*\z/.match?(hex) # `hex.length % 2 !== 0` (RuboCop `Style/EvenOdd`)
      raise "Invalid hex string: #{hex.inspect} (must be lowercase, even length)" # `JSON.stringify(hex)` is `inspect`
    end

    # the `Uint8Array` of `hex.length / 2` bytes is a binary String: two hex digits per byte
    return [hex].pack('H*')
  end

  def make_random_source(hex, test_name)
    bytes = hex_to_bytes(hex)
    pos = 0
    # the Ruby `randomSource` contract: the callable receives the byte count `n` and returns the bytes (JS fills `arr` in place)
    return lambda do |n|
      if pos + n > bytes.bytesize
        need = n
        have = bytes.bytesize - pos
        raise "Random byte stream exhausted (test \"#{test_name}\"): needed #{need} bytes, #{have} remaining"
      end

      out = bytes.byteslice(pos, n)
      pos += n
      return out
    end
  end

  # Stage 1 mints a fresh key pair for every challenge, so a stage-1 result carries random values: the `ek` inside the
  # challenge, the decryption key after the challenge's `.`, and the sealed request of a flow that follows a sign-in. The runner checks
  # each one, then puts a fixed placeholder in its place (EK, DK, HMAC) before comparing.
  # `maskStage1` asserts, so it is an instance method of a module that every suite's `describe` includes (a `module_function` cannot assert)
  module Masking
    def mask_stage1(result, options)
      # `!result || typeof result.challenge !== 'string' || typeof result.redirectUrl !== 'string'`: a stage-1 result is a Hash of two Strings
      if !result.is_a?(Hash) || !Triauth::Helpers.is_string(result[:challenge]) || !Triauth::Helpers.is_string(result[:redirectUrl])
        return result
      end

      challenge, decryption_key = result[:challenge].split('.', -1) # a non-empty String (the stage-1 shape); `-1` under the split rule
      json = Triauth::Helpers.base64url_to_string(challenge)
      ek = json[/"ek":"([A-Za-z0-9_-]{87})"/, 1] # `(json.match(re) || [])[1]`: nil for no match
      assert(!ek.nil? && json.split('"ek":', -1).length == 2, 'a stage-1 challenge carries exactly one ek')

      # The key pair works: a probe sealed to ek opens with the decryption key
      probe = Triauth::ResponseCipher.seal(ek, 'probe')[:sealedResponse]
      assert_equal 'probe', Triauth::ResponseCipher.open(ek, decryption_key, probe)[:response]

      masked = Triauth::Helpers.string_to_base64url(json.sub("\"ek\":\"#{ek}\"", '"ek":"EK"')) # JS string `replace`: the first occurrence
      redirect_url = result[:redirectUrl].sub("challenge=#{challenge}", "challenge=#{masked}")

      # A request that follows a sign-in has the challenge sealed under the session key, next to the key's skid
      request = redirect_url[/[#?&]request=([^&]*)/, 1]
      if !request.nil? # `request !== undefined`
        session_key = options[:sessionKey].split(':', -1).last # `.split(':').pop()`; `options` is `t[:args][0]`, a Hash in every stage-1 case that reaches here
        skid = redirect_url[/[#?&]skid=([^&]*)/, 1]
        assert_equal Triauth::RequestCipher.skid(session_key), skid, 'skid identifies the session key'
        assert_equal challenge, Triauth::RequestCipher.open(session_key, request), 'the request opens to the challenge'
        redirect_url = redirect_url.sub("request=#{request}", 'request=REQUEST')
      end

      return result.merge({ challenge: "#{masked}.DK", redirectUrl: redirect_url }) # `{...result, ...}`: a new Hash
    end
  end

  # `isDeepEqual` served RECORD mode only: dropped

  # The drop-null normalization applied to both sides of the comparison: a Hash becomes a new Hash of its
  # non-nil members, each normalized; an Array is mapped; anything else is returned as it is.
  def normalize(value)
    if value.is_a?(Hash)
      return value.each_with_object({}) { |(k, v), h| h[k] = normalize(v) if !v.nil? }
    elsif value.is_a?(Array)
      return value.map { |v| normalize(v) }
    end

    return value
  end
end

suites.each do |suite|
  file = suite[:file]
  data = suite[:data]

  describe(data[:title].nil? || data[:title].empty? ? file : data[:title]) do # `data.title || file`: the JS falsy set of a string
    include JsonSuiteRunner::Masking # `maskStage1` asserts: its assertions run as the spec's

    # `suiteTouched` served RECORD mode only: dropped

    data[:tests].each do |t|
      it t[:name] do
        # `typeof fn !== 'function'`: the API method must exist on the module
        if !Triauth.respond_to?(t[:call])
          raise "Unknown Triauth method: #{t[:call]}"
        end

        if !t[:args].is_a?(Array)
          raise "Test \"#{t[:name]}\": args must be an array"
        end

        effective_time = t.key?(:currentTime) ? t[:currentTime] : data[:currentTime]
        effective_dns  = Triauth::Helpers.object_assign({}, data[:dnsEntries], t[:dnsEntries]) # a nil per-test patch contributes nothing; a `null` domain stays a nil member (the stub answers `[]`)
        random_source  = t[:random].nil? || t[:random] == '' ? nil : JsonSuiteRunner.make_random_source(t[:random], t[:name]) # `t.random ?`: the JS falsy set of a string

        saved_now      = Triauth::Helpers.method(:date_now)
        saved_resolver = Triauth.config[:resolver]
        saved_random   = Triauth.config[:randomSource]

        Triauth::Helpers.define_singleton_method(:date_now) { effective_time } # `Date.now = () => effectiveTime`
        Triauth.config[:resolver]     = DnsResolverStub.new(effective_dns)
        Triauth.config[:randomSource] = random_source

        begin
          result = mask_stage1(Triauth.public_send(t[:call], *t[:args]), t[:args][0]) # `maskStage1(await fn(...t.args), t.args[0])`: nil for a no-argument case, read only past the guard
          # the RECORD branch has no counterpart; `assert.deepStrictEqual(result, t.expected)` under the drop-null normalization
          assert_equal JsonSuiteRunner.normalize(t[:expected]), JsonSuiteRunner.normalize(result)
        ensure
          Triauth::Helpers.define_singleton_method(:date_now, saved_now)
          Triauth.config[:resolver]     = saved_resolver
          Triauth.config[:randomSource] = saved_random
        end
      end
    end

    # the `after` hook wrote the suite back in RECORD mode only: dropped
  end
end
