# frozen_string_literal: true

require_relative '../setup'
require 'uri'

module TestInternals
  def self.canonical_url
    describe 'Triauth.Helpers (canonical URLs)' do
      # The one accepted spelling of each resource — every entry must pass isCanonicalUrl.
      canonical_urls = [
        'https://example.com/',
        'https://example.com/cb',
        'https://example.com/app/callback',
        'https://example.com/license.txt',
        'https://example.org/cb',
        'https://other-domain.com/',
        'https://attest.triauthdemo.org/not-a-robot',
        'https://triauthdemo.org/p',
        'http://localhost/',
        'http://localhost:3000/cb',
        'http://localhost:8080/verify',
        'http://localhost:8080/playground/',
        'http://example.com/cb',
        'http://intranet.corp.example/wiki',
        'https://intranet/',
        'https://a.b/',
        'https://1.example.com/',
        'https://a.com:8443/x',
        'https://a.com:80/x',
        'http://a.com:443/x',
        'https://127.0.0.1/',
        'http://192.168.0.14/cb',
        'http://10.0.0.5:8080/cb',
        'https://100.64.7.13:8443/login',
        'https://a.com//double//slash',
        'https://a.com/f%2Fx',
        'https://a.com/%41bc',
        'https://a.com/~tilde/*star/(par)en/pl+us/co:lon/at@sign/eq=uals/do$llar/am&p/co,mma/ex!cl',
        'https://example.com/cb;sid=1',
        'https://example.com/a;b/cb',
        "https://x.com/a'b",
        'https://a.com/?q;x',
        "https://a.com/?q'x",
        'https://example.com/cb?a=1;b=2',
        'https://a.com/#f;x',
        "https://a.com/#f'x",
        'https://example.com/cb?a=b&c=d',
        'https://example.com/cb?X-Amz-Signature=abc',
        'https://example.com/cb#frag',
        'https://example.com/cb?x=1#y',
        'https://example.com/cb#f?x',
        'https://raw.githubusercontent.com/spdx/license-list-data/refs/heads/main/text/AGPL-3.0-or-later.txt',
        "https://example.com/#{'a' * 2028}" # exactly LIMITS.urlBytesize (2048) bytes
      ]

      # Non-canonical or out-of-grammar spellings — every entry must be rejected.
      rejected_urls = {
        'scheme' => [
          'HTTPS://example.com/', 'Https://example.com/', 'HTTP://example.com/', 'ftp://example.com/',
          'wss://example.com/', 'example.com/', '//example.com/', 'https:/example.com/'
        ],
        'host' => [
          'https://A.COM/', 'https://Example.com/', 'https://a.com./', 'https://.a.com/', 'https://a..com/',
          'https://_x.a.com/', 'https://-a-.com/', 'https://a-.com/', 'https://-a.com/',
          "https://#{'a' * 64}.com/", 'https://', 'https:///', 'https://:8080/'
        ],
        # an IPv4 host has exactly one grammar spelling — the dotted quad; every other notation is out
        'exotic-ip-spellings' => [
          'https://[::1]/', 'https://0x7f.0x1/', 'https://1.2.3.04/', 'https://example.12/',
          'https://2130706433/', 'https://0177.0.0.1/', 'https://a.0x/', 'https://256.1.1.1/',
          'https://1.2.3/', 'https://1.2.3.4.5/', 'https://0x7f.0x0.0x0.0x1/', 'https://010.0.0.1/'
        ],
        'punycode' => [
          'https://xn--mller-kva.de/cb', 'https://a.xn--p1ai/', 'https://XN--mller-kva.de/'
        ],
        'port' => [
          'https://a.com:443/', 'http://localhost:80/', 'https://a.com:08080/', 'https://a.com:65536/',
          'https://a.com:/', 'https://a.com:8_0/', 'https://a.com:0/'
        ],
        'userinfo' => [
          'https://user:pass@example.com/p', 'https://user@example.com/', 'https://@example.com/'
        ],
        # characters outside the RFC 3986 pchar set — the envelope wrapper '|' among them
        'charset' => [
          'https://a.com/a|b', 'https://example.com/a|b/cb', 'https://a.com/a[b]c', 'https://a.com/{x}',
          'https://a.com/a\\b', 'https://a.com/a^b', 'https://a.com/a`b', 'https://a.com/"x"',
          'https://a.com/<y>', 'https://a.com/?q|x', 'https://a.com/?q[x]', 'https://a.com/#f|x',
          'https://a.com/#f#g'
        ],
        'dot-segments' => [
          'https://a.com/./b', 'https://a.com/../b', 'https://a.com/a/..', 'https://a.com/%2e/b',
          'https://a.com/a/%2e%2E/b', 'https://a.com/.%2E/b', 'https://a.com/%2E%2e/'
        ],
        'structure' => [
          'https://example.com', 'https://example.com?x=1', 'https://example.com#f',
          'https://a.com/?', 'https://a.com/#', 'https://a.com/?#'
        ],
        'encoding-and-size' => [
          'https://a.com/%zz', 'https://a.com/%2', 'https://a.com/100%', 'https://a.com/é',
          'https://müller.de/', 'https://a.com/a b', "https://a.com/a\tb", '',
          "https://example.com/#{'a' * 2029}" # one byte over LIMITS.urlBytesize
        ]
      }

      describe 'isCanonicalUrl' do
        it 'accepts the canonical spelling of http(s) URLs, named and IPv4-literal hosts alike' do
          canonical_urls.each do |url|
            assert_equal true, Triauth::Helpers.is_canonical_url(url), url
          end
        end

        rejected_urls.each do |rule, urls|
          it "rejects out-of-grammar spellings: #{rule}" do
            urls.each do |url|
              assert_equal false, Triauth::Helpers.is_canonical_url(url), url
            end
          end
        end

        it 'rejects non-string input' do
          [123, nil, {}, ['https://example.com/'], true].each do |value|
            assert_equal false, Triauth::Helpers.is_canonical_url(value), value.to_s
          end
        end
      end

      describe 'isSecureUrl' do
        # Secure-origin URLs: https on a named host, or http on the literal localhost. This is the
        # acceptance rule for verbatim trust anchors (attestation provider URLs).
        secure_urls = [
          'https://example.com/', 'https://attest.triauthdemo.org/not-a-robot', 'https://triauthdemo.org/p',
          'https://a.com:8443/x', 'https://intranet/', 'http://localhost/', 'http://localhost:8080/verify'
        ]

        # Canonical, but not secure-origin: http off localhost, or an IP-literal host on any scheme.
        canonical_not_secure_urls = [
          'http://example.com/cb', 'http://intranet.corp.example/wiki', 'http://192.168.0.14/cb',
          'http://10.0.0.5:8080/cb', 'https://127.0.0.1/', 'https://100.64.7.13:8443/login'
        ]

        it 'accepts canonical https URLs on named hosts, and http on the literal localhost' do
          secure_urls.each do |url|
            assert_equal true, Triauth::Helpers.is_secure_url(url), url
          end
        end

        it 'rejects canonical URLs that are http off localhost or carry an IP-literal host' do
          canonical_not_secure_urls.each do |url|
            assert_equal false, Triauth::Helpers.is_secure_url(url), url
            assert_equal true, Triauth::Helpers.is_canonical_url(url), "still canonical: #{url}"
          end
        end

        it 'is a strict narrowing of isCanonicalUrl: never accepts what the grammar rejects' do
          [*canonical_urls, *rejected_urls.values.flatten(1), 42, nil, ''].each do |url|
            if Triauth::Helpers.is_secure_url(url)
              assert_equal true, Triauth::Helpers.is_canonical_url(url), url.to_s[0, 60]
            end
          end
        end
      end

      describe 'getBaseUrl' do
        it 'returns the origin plus the path through the last "/"' do
          cases = [
            ['https://example.com/cb', 'https://example.com/'],
            ['https://example.com/', 'https://example.com/'],
            ['https://example.com/app/callback', 'https://example.com/app/'],
            ['https://example.com/app/', 'https://example.com/app/'],
            ['http://localhost:3000/cb', 'http://localhost:3000/'],
            ['http://10.0.0.5:8080/cb', 'http://10.0.0.5:8080/'],
            ['https://a.com:8443/x/y/z', 'https://a.com:8443/x/y/'],
            ['https://a.com/x/y/z?q=1#f', 'https://a.com/x/y/'],
            ['https://example.com/cb;sid=1', 'https://example.com/'],
            # the helper is a pure view: a ';' in the base span parses fine here, and it is the
            # callbackUrl validator that refuses to let such a base become a `via`
            ['https://example.com/a;b/cb', 'https://example.com/a;b/']
          ]
          cases.each do |url, base|
            assert_equal base, Triauth::Helpers.get_base_url(url), url
          end
        end

        it 'returns false for anything that is not a canonical URL — the policy checks included' do
          [
            'not-a-url', 'https://u:p@a.com/x', 'https://A.COM/x', 'https://example.com', 'https://a.com/a|b/cb', 42, nil,
            # policy-layer rejects share the same accept-set as isCanonicalUrl (no grammar-only backdoor)
            'https://xn--mller-kva.de/x', 'https://a.com/%zz/x', 'https://0x7f.0x1/x', "https://example.com/#{'a' * 2029}"
          ].each do |url|
            assert_equal false, Triauth::Helpers.get_base_url(url), url.to_s[0, 60]
          end
        end
      end

      describe 'urlHost' do
        it 'returns the port-free lowercase host of a canonical URL' do
          cases = [
            ['https://attest.triauthdemo.org/over-18', 'attest.triauthdemo.org'],
            ['http://localhost:8080/verify', 'localhost'],
            ['https://a.com:8443/x', 'a.com'],
            ['https://127.0.0.1/', '127.0.0.1'],
            ['http://10.0.0.5:8080/cb', '10.0.0.5']
          ]
          cases.each do |url, host|
            assert_equal host, Triauth::Helpers.url_host(url), url
          end
        end

        it 'returns false for anything that is not a canonical URL — the policy checks included' do
          ['https://2130706433/', 'nope', '', nil, 'https://xn--mller-kva.de/x', 'https://a.com/%zz/x'].each do |url|
            assert_equal false, Triauth::Helpers.url_host(url), url.to_s
          end
        end
      end

      describe 'hasPunycodeLabel' do
        it 'flags xn-- labels in any position, case-insensitively' do
          ['xn--mller-kva.de', 'a.xn--p1ai', 'XN--mller-kva.de', 'a.XN--p1ai.com'].each do |host|
            assert_equal true, Triauth::Helpers.has_punycode_label(host), host
          end
          ['example.com', 'axn--b.com', 'xn.example.com', 42, nil].each do |host|
            assert_equal false, Triauth::Helpers.has_punycode_label(host), host.to_s
          end
        end
      end

      describe 'isDomainName' do
        it 'accepts LDH domain names of at least two labels, case-insensitively' do
          ['example.com', 'auth.example.com', 'AUTH.Uppercase.Example', '1.example.com', 'a-b.example.co'].each do |domain|
            assert_equal true, Triauth::Helpers.is_domain_name(domain), domain
          end
        end

        it 'rejects punycode labels and numeric final labels (IPv4 spellings)' do
          ['xn--mller-kva.de', 'a.xn--p1ai', 'a.example.12', '0x7f.0x1', 'a.0x7F', 'example.0x', 'localhost', 'a.com.', 'port.example:8443'].each do |domain|
            assert_equal false, Triauth::Helpers.is_domain_name(domain), domain
          end
        end

        it 'bounds a name at 253 bytes, the DNS maximum' do
          labels = "#{'a' * 63}.#{'b' * 63}.#{'c' * 63}."
          assert_equal true, Triauth::Helpers.is_domain_name(labels + ('d' * 61)), '253 bytes'
          assert_equal false, Triauth::Helpers.is_domain_name(labels + ('d' * 62)), '254 bytes'
        end
      end

      # The closed grammar must never be the looser side of a parser differential: everything it
      # accepts must also survive a WHATWG-URL round-trip canonicality check (re-serialization
      # equality), and on that accepted set both parsers must extract identical components. Runs
      # against the runtime's own URL implementation — Node and browsers each cross-check it.
      # Ruby has no WHATWG URL parser: the oracle here is the RFC 3986 parser behind `URI.parse`
      # (`URI::RFC3986_Parser`), a weaker but real cross-check.
      describe 'grammar vs WHATWG URL (differential)' do
        whatwg_is_canonical_url = lambda do |string|
          return false if !Triauth::Helpers.is_string(string)
          return false if string.length == 0 || Triauth::Helpers.byte_size(string) > Triauth::LIMITS[:urlBytesize]
          return false if !/\A[\x21-\x7E]+\z/.match?(string)
          return false if /%(?![0-9A-Fa-f]{2})/.match?(string)

          url = begin
            URI.parse(string)
          rescue URI::InvalidURIError
            nil
          end
          return false if url.nil? || url.host.nil? || /(\A[xX][nN]--)|(\.[xX][nN]--)/.match?(url.host)

          # `URI` percent-encodes "'" in http(s) queries (as WHATWG does with its special-query set); the closed
          # grammar keeps the RFC 3986 pchar set, where "'" is legal — accept exactly that one
          # spelling difference and no other.
          return url.userinfo.nil? &&
                 (url.to_s == string || url.to_s == string.gsub("'", '%27'))
        end

        whatwg_get_base_url = lambda do |string|
          url = URI.parse(string)
          pathname = url.path
          url.path = pathname.end_with?('/') ? pathname : pathname[0, (pathname.rindex('/') || -1) + 1]
          url.userinfo = nil
          url.fragment = nil
          url.query = nil
          url.to_s
        rescue URI::InvalidURIError, URI::InvalidComponentError
          false
        end

        corpus = [
          *canonical_urls,
          *rejected_urls.values.flatten(1),
          # WHATWG-canonical strings deliberately outside the closed grammar
          'https://a.com/a|b', 'https://a.com/a[b]c', 'https://a.com/?q|pipe', 'https://a.com/?q^caret',
          'https://a.com/?q{cur}', 'https://a.com/?q`tick', 'https://a.com/?q\\back', 'https://a.com/#f|pipe',
          'https://a.com/#f\\back', 'https://a.com/#f^caret', 'https://a.com./',
          'https://_x.a.com/', 'https://-a-.com/', 'https://a.com/?', 'https://a.com/#',
          # and assorted hostile spellings
          'https://a.com\\b/', 'https://a.com/%2e%2e/%2e%2e/etc', 'https://0x7f.1/', 'https://a.com:0443/',
          'http://LOCALHOST/', 'http://localhost./', 'https://a.com/..%2f..', "https://e.com/?'or 1=1--"
        ]

        it 'never accepts a string the WHATWG round-trip check rejects' do
          corpus.each do |s|
            if Triauth::Helpers.is_canonical_url(s)
              assert_equal true, whatwg_is_canonical_url.call(s), "accepted, but WHATWG-non-canonical: #{s}"
            end
          end
        end

        it 'extracts the same base URL and host as WHATWG parsing on every accepted URL' do
          corpus.each do |s|
            if Triauth::Helpers.is_canonical_url(s)
              assert_equal whatwg_get_base_url.call(s), Triauth::Helpers.get_base_url(s), "base of #{s}"
              assert_equal URI.parse(s).host, Triauth::Helpers.url_host(s), "host of #{s}"
            end
          end
        end

        it 'exposes one accept-set: getBaseUrl and urlHost succeed exactly when isCanonicalUrl accepts' do
          corpus.each do |s|
            canonical = Triauth::Helpers.is_canonical_url(s)
            assert_equal canonical, Triauth::Helpers.get_base_url(s) != false, "getBaseUrl vs isCanonicalUrl on #{s.to_s[0, 60]}"
            assert_equal canonical, Triauth::Helpers.url_host(s) != false, "urlHost vs isCanonicalUrl on #{s.to_s[0, 60]}"
          end
        end
      end
    end
  end
end

TestInternals.canonical_url if __FILE__ == $PROGRAM_NAME
