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


require 'securerandom'
require_relative 'base'
require_relative '../helpers'
require_relative '../protocol'

module Triauth
  module Resolvers
    # A base class for DNS resolvers based on JSON API for DNS over HTTPS (DoH).
    #
    # It provides a basic implementation of the `resolve` method that uses the JSON API endpoint URL which is expected
    # to be set by child classes through the `super(endpoint_url, options = {})` call in their respective constructors.
    #
    # @see https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers A comprehensive list of public DoH servers.
    #   Some of them may offer JSON API that allows cross-origin requests.
    class DnsJson < Base
      # @return [String] The base URL of the DoH API endpoint.
      attr_reader :url
      # @return [Hash] The resolver options passed to the constructor.
      attr_reader :options

      # @param url [String] A base URL of the DoH API endpoint
      # @param options [Hash] Defaults to `{}`.
      # @option options [Boolean] :skipPadding Set to true if you want to omit using random padding in the fetch url.
      #   Random padding helps to prevent side-channel privacy attacks based on statistical analysis of the HTTPS payload.
      # @option options [Integer] :retries How many times to retry if name resolution fails. Defaults to 0.
      # @option options [Integer] :retryDelay If failure may be recoverable with time, how long to wait between retries in ms. Defaults to 150.
      # @option options [Integer] :timeout How long to wait (ms) before aborting the HTTP fetch request. Defaults to nil.
      #   It bounds every phase of the request (connect, write, each read) and the whole body read; nil leaves the
      #   transport's own per-phase defaults (60 s) in place.
      # @option options [Proc] :fetch A fetch implementation to use instead of `Triauth::Helpers.fetch`: a callable with the
      #   same contract (`call(url, fetch_options) { |response| }`, see {Triauth::Helpers.fetch}). Lets constrained runtimes
      #   inject their own client. Defaults to `Triauth::Helpers.fetch`.
      # @option options [Boolean] :normalizeTxtRecords Set to true to convert presentation-form TXT data — each 255-octet character-string wrapped
      #   in double-quotes, e.g. `"part1" "part2"` — into the record's logical content: the character-string
      #   contents concatenated in order with no separator (some DoH providers return presentation form).
      # @option options [Boolean] :decodeTxtRecords Set to true to decode RFC 1035 presentation-format escapes in TXT records - `\NNN` (exactly three
      #   decimal digits) into that octet, `\X` into X literally — and reinterpret the result as utf-8
      #   (some DoH providers escape non-printable ASCII). A record carrying a malformed escape
      #   (`\NNN` above 255, fewer than three digits, a bare trailing backslash) is ignored as a whole.
      def initialize(url, options = {})
        super()
        @url = url
        @options = options
      end

      # Folds a DNS name for comparison: ASCII-lowercased, without the trailing dot of the absolute form.
      # DNS names compare without regard to ASCII case, and a server may spell the owner name of an answer
      # in another case than the query.
      #
      # @param name [String] A DNS name as queried, or as returned in an answer.
      # @return [String] The folded name.
      def self.fold_name(name)
        return Helpers.ascii_lowercase(name.end_with?('.') ? name[0...-1] : name)
      end

      # Converts a TXT record's presentation form into its logical content.
      #
      # DoH JSON providers that emit presentation form wrap each 255-octet character-string in
      # double-quotes and separate consecutive strings with whitespace (`"part1" "part2"`),
      # escaping a literal quote as `\"` and a literal backslash as `\\` inside a string.
      # The record's logical content is the in-order, no-separator concatenation of the
      # character-string contents. Because `\"`, `\\` and decimal `\NNN` escapes all live at the
      # same level of the presentation grammar, they must be decoded in a single pass: with
      # `keep_escapes` set, `\"` and `\\` sequences are kept verbatim in the output (they still
      # delimit correctly) so that the decodeTxtRecords stage decodes every escape at once;
      # without it, they decode to their literal characters here.
      #
      # Data that does not start with a double-quote is already logical content and is returned
      # unchanged. Data that starts like presentation form but does not parse as a sequence of
      # quoted strings (e.g., an unterminated quote) is returned unchanged, so downstream record
      # parsing rejects it instead of consuming a half-normalized value.
      #
      # @param data [String] The `Answer[].data` field of a TXT answer.
      # @param keep_escapes [Boolean] Set to true to keep `\"`/`\\` escape sequences verbatim
      #   in the output, for a subsequent single-pass escape decode. Defaults to false.
      # @return [String] The logical record content.
      def self.normalize_txt_data(data, keep_escapes = false)
        # `data[i]` is one character here (a UTF-16 unit in JS); every comparison is to an ASCII character, so the walk is equivalent
        if data.length < 2 || data[0] != '"'
          return data
        end

        content = +''
        i = 0

        while i < data.length
          # Each pass consumes one double-quoted character-string, then any inter-string whitespace
          if data[i] != '"'
            return data
          end

          i += 1

          while i < data.length && data[i] != '"'
            if data[i] == '\\' && (data[i + 1] == '"' || data[i + 1] == '\\')
              content << (keep_escapes ? data[i] + data[i + 1] : data[i + 1])
              i += 1
            else
              content << data[i]
            end
            i += 1
          end

          if i >= data.length
            return data
          end

          i += 1

          i += 1 while i < data.length && (data[i] == ' ' || data[i] == "\t")
        end

        return content
      end

      # Queries the DNS for resource records of a given type that are stored under a given domain name.
      #
      # @param domain_name [String] A domain name to query the DNS for. For example "example.com".
      # @param type [String] A type of DNS resource record to look for. For example "TXT", or "A".
      # @param options [Hash] Overrides for the options passed to the constructor that will be effective during this function call. Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Array<Hash>] The array of retrieved DNS resource records in `{value, ttl, dnssec}` format;
      #   `ttl` and `dnssec` carry the provider's `TTL` and `AD` fields, and stay nil where the provider omits them.
      def resolve(domain_name, type, options = {}, config = {})
        config = Helpers.merge_config(config)

        options = Helpers.object_assign({
                                          retries: 0,
                                          retryDelay: 150,
                                          skipPadding: false,
                                          timeout: nil,
                                          # `signal: null` has no counterpart: there is no abort signal here
                                          fetch: nil
                                        }, @options, options)

        # Ensure type is upper-case
        type = type.to_s.upcase

        # `return new Promise((resolve, reject) => {...})`: the promise body runs inline below; `resolve(x)` is `return x`, `reject(err)` is `raise err`

        # Browsers and Node expose a global `fetch`; constrained runtimes may inject one through options.fetch.
        fetch_impl = options[:fetch] || Helpers.method(:fetch)
        # the `typeof fetch !== 'undefined'` detection and the 'No fetch implementation available' rejection have no counterpart: the default transport always exists

        fetch_url = "#{@url}?name=#{Helpers.encode_uri_component(domain_name)}&type=#{Helpers.encode_uri_component(type)}"

        # Use random padding to limit the scope for side-channel privacy attacks that use the packet sizes of HTTPS GET requests.
        # Uses crypto.getRandomValues so the padding cannot be predicted from a known-plaintext leak.
        if !options[:skipPadding]
          chars = 'abcdefghijklmnopqrstuvwxyz'
          fetch_url += "&random_padding="
          needed = (50 - (fetch_url.length % 50)) % 50
          if needed > 0
            rnd = SecureRandom.random_bytes(needed).bytes
            needed.times do |i|
              fetch_url += chars[rnd[i] % chars.length]
            end
          end
        end

        # The AbortController, the timeout timer, the `onAbort` listener and `cleanup` have no counterpart: the deadline
        # checked between body chunks below and the transport's per-phase timeouts (`fetch_options[:timeout]`) replace them.
        # `timeout` 0 is "no timer" in JS (`if (abortController && options.timeout)`), so it leaves the transport's defaults too.
        # `Accept-Encoding: identity`: the body is counted as received, so no compressed body may expand past the cap.
        fetch_options = { headers: { 'Accept' => 'application/dns-json', 'Accept-Encoding' => 'identity' }, timeout: options[:timeout] == 0 ? nil : options[:timeout] }
        started = Helpers.now

        begin
          text = fetch_impl.call(fetch_url, fetch_options) do |response|
            # The deadline stays armed across the entire body read (it is checked before each chunk is kept),
            # bounding slow-body delivery (server sends headers fast, then dribbles bytes).
            if !response.ok
              raise "DoH request failed with HTTP #{response.status}"
            end

            # Bail early when the server *declares* an over-limit body.
            declared = response.headers['content-length'].to_s[/\A[0-9]+/]&.to_i
            if !declared.nil? && declared > Protocol::LIMITS[:jsonMaxBytesize]
              # `abortController?.abort(...)` has no counterpart: raising inside the block is the abort (the connection is closed)
              raise 'DoH response exceeds size limit (Content-Length)'
            end

            # Prefer incremental streaming when supported; fall back to .text() if not
            if response.respond_to?(:each_chunk)
              chunks = []
              received = 0

              response.each_chunk do |value|
                if !options[:timeout].nil? && options[:timeout] != 0 && Helpers.now - started > options[:timeout]
                  raise 'Resolver timeout'
                end

                # Check BEFORE accumulating the over-limit chunk so we never hold it.
                if received + value.bytesize > Protocol::LIMITS[:jsonMaxBytesize]
                  raise 'DoH response exceeds size limit'
                end

                received += value.bytesize
                chunks.push(value)
              end
              # `reader.releaseLock()` has no counterpart: the block-driven stream releases itself

              # Assemble and decode once — multi-byte sequences may span chunk boundaries.
              # Strict: a body that is not well-formed UTF-8 rejects the whole response
              # (propagates to the retry/reject path below, like any transport failure).
              Helpers.utf8_bytes_to_string(chunks.join)

            elsif response.respond_to?(:text)
              text = response.text
              if Helpers.byte_size(text) > Protocol::LIMITS[:jsonMaxBytesize]
                raise 'DoH response exceeds size limit'
              end

              text

            else
              raise 'DoH response has no readable body'
            end
          end
        rescue StandardError => err
          # the JS `.catch` for the request and the body read: logged, then retried while the budget lasts (no delay on this path)
          Helpers.log(config, :debug, err)

          # `options.signal?.aborted` has no counterpart: there is no abort signal
          if options[:retries] <= 0
            raise err

          else
            options[:retries] -= 1

            return resolve(domain_name, type, options, config)
          end
        end

        # `try { ... } catch (err) { return reject(err) }`: a parse failure is terminal; it propagates past the retry rescue below, which covers the answer loop only
        json = Helpers.safe_parse_json(text)

        # Check for error response status code(s), and act appropriately
        # @see DNS status codes - http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6

        # for NXDOMAIN return empty array
        if json[:Status] == 3
          return []

        # for other errors, retry and if still error, fail
        elsif json[:Status] != 0
          if options[:retries] <= 0
            raise "DoH response carries DNS status #{json[:Status]}"

          else
            options[:retries] -= 1

            if !options[:retryDelay].nil? && options[:retryDelay] != 0
              sleep(options[:retryDelay] / 1000.0)
            end

            return resolve(domain_name, type, options, config)
          end
        end

        begin
          # The status code is 0 - all fine, continue to extract and parse the answer
          retval = []
          dns_record_types = {
            TXT: 16,
            A: 1,
            AAAA: 28,
            CNAME: 5
          }

          queried_name = DnsJson.fold_name(domain_name)

          # `for (const a of (json['Answer'] || []))`: the JS falsy set of a parsed JSON value (nil, false, 0, '') iterates
          # nothing, an Array iterates its elements and a String its characters (none of which is an answer), and anything
          # else (a Hash included) is not iterable there and throws into the retry path below
          answer = json[:Answer]
          answer = [] if answer.nil? || answer == false || answer == 0 || answer == ''
          answer = answer.chars if answer.is_a?(String)
          if !answer.is_a?(Array)
            raise TypeError, "json['Answer'] is not iterable"
          end

          answer.each do |a|
            # `a['name']` of a non-object is undefined in JS, so such an answer fails the name check below; a null answer throws there, as `nil[:name]` does here
            if !a.nil? && !a.is_a?(Hash)
              next
            end

            # Ensure the response is for the correct domain
            if !Helpers.is_string(a[:name]) || DnsJson.fold_name(a[:name]) != queried_name
              next
            end

            # Ensure the response has the requested record type
            if dns_record_types[type.upcase.to_sym] != a[:type]
              next
            end

            # Ensure the response has fields of expected types
            if !Helpers.is_string(a[:data]) ||
               (!Helpers.is_integer(a[:TTL]) || a[:TTL] < 0) ||
               !(json[:AD] == true || json[:AD] == false)
              next
            end

            # Convert presentation-form TXT data into the record's logical content if normalizeTxtRecords is set;
            # when the decode stage below will run, escapes stay verbatim so it can decode them in one pass
            if a[:type] == 16 && options[:normalizeTxtRecords]
              a[:data] = DnsJson.normalize_txt_data(a[:data], options[:decodeTxtRecords])
            end

            # Decode escaped chars: one left-to-right pass over the RFC 1035 escape grammar —
            # `\DDD` (exactly three digits, one octet) yields that byte, `\X` yields X literally,
            # and anything else (`\DDD` above 255, fewer than three digits, a bare trailing
            # backslash) rejects the record as a whole rather than guessing
            if a[:type] == 16 && options[:decodeTxtRecords]
              begin
                bytes = a[:data].gsub(/\\([0-9]{3})|\\([^0-9])?/) do
                  ddd = Regexp.last_match(1)
                  ch = Regexp.last_match(2)
                  if !ddd.nil?
                    code = Integer(ddd, 10)
                    if code > 255
                      raise 'Invalid \\DDD escape in a TXT record'
                    end

                    next code.chr(Encoding::UTF_8)
                  end
                  if ch.nil?
                    raise 'Truncated escape in a TXT record'
                  end

                  next ch
                end
                # One-char-per-octet contract: a char above U+00FF is not an octet, so it rejects
                # the record rather than wrapping mod-256 into an unrelated byte
                a[:data] = Helpers.utf8_bytes_to_string(bytes.each_char.map do |c|
                  byte = c.ord
                  if byte > 255
                    raise 'Non-octet character in a TXT record escape decode'
                  end

                  next byte
                end.pack('C*'))
              rescue StandardError => err
                Helpers.log(config, :debug, 'DNS TXT record could not be decoded', { cause: err })
                next
              end
            end

            retval.push({ value: a[:data], ttl: a[:TTL], dnssec: json[:AD] })
          end

          return retval
        rescue StandardError => err
          # the JS `.catch` for the answer loop: a throw inside it is logged, then retried while the budget lasts
          Helpers.log(config, :debug, err)

          if options[:retries] <= 0
            raise err

          else
            options[:retries] -= 1

            return resolve(domain_name, type, options, config)
          end
        end
      end
    end
  end
end
