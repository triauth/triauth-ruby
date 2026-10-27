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


require 'resolv'
require 'socket'
require_relative 'base'
require_relative '../helpers'

module Triauth
  module Resolvers
    # A DNS resolver that uses the Ruby standard library's `Resolv::DNS` to perform queries.
    # This resolver works with the system's configured nameservers (`/etc/resolv.conf`, or the registry on Windows).
    #
    # @see https://docs.ruby-lang.org/en/3.2/Resolv/DNS.html Documentation
    class SystemDns < Base
      # @return [Hash] The resolver options passed to the constructor.
      attr_reader :options

      # @param options [Hash] Defaults to `{}`.
      # @option options [Integer] :tries How many times each name server is tried before the query fails
      #   (`ARES_OPT_TRIES`; this works differently than `retries` in DnsJson). Defaults to 3.
      # @option options [Integer] :timeout How long to wait (ms) for a single try before it counts as failed.
      #   Defaults to nil, which leaves the `Resolv::DNS` default (5 s per try) in place.
      def initialize(options = {})
        super()
        @options = options
        # `this.dns = null` has no counterpart: `resolv` is loaded with the file, there is nothing to load lazily
      end

      # `#loadDns` has no counterpart: `require 'resolv'` above is the whole load, and there is no browser lane

      # Queries the DNS for resource records of a given type that are stored under a given domain name,
      # through the Ruby `Resolv::DNS` resolver.
      #
      # @param domain [String] A domain name to query the DNS for.
      # @param type [String] A type of DNS resource record to look for; only 'TXT' is supported.
      # @param options [Hash] Per-call overrides for the resolver options passed to the constructor. Defaults to `{}`.
      # @param config [Hash] Optional overrides for the global Triauth.config settings. Defaults to `{}`.
      #
      # @return [Array<Hash>] The array of retrieved DNS resource records in `{value, ttl, dnssec}`
      #   format. `Resolv::DNS` reports the TTL of every resource record but no DNSSEC status, so `ttl` carries the
      #   record's TTL in seconds and `dnssec` is always nil, and a record whose bytes are not well-formed UTF-8 is
      #   left out of the answer. Every TXT record of the reply's answer section is returned whatever its owner name,
      #   as `node:dns` does, so a name that is a CNAME alias resolves to its target's TXT records. A missing name
      #   (NXDOMAIN) and a name with no records of this type (NODATA) both resolve to an empty array. It raises for a
      #   non-TXT query type, and upon any other resolver error.
      def resolve(domain, type, options = {}, config = {})
        config = Helpers.merge_config(config)

        options = Helpers.object_assign({
                                          tries: 3, # this works differently than "retries" in dns_json - @see ARES_OPT_TRIES on https://manpages.ubuntu.com/manpages/oracular/en/man3/ares_init_options.3.html
                                          timeout: nil
                                          # `signal: null` has no counterpart: there is no abort signal here
                                        }, @options, options)

        # `return new Promise((resolve, reject) => {...})`: the promise body runs inline below; `resolve(x)` is `return x`, `reject(err)` is `raise err`

        # the `typeof window` rejection has no counterpart: there is no browser lane

        if type != 'TXT'
          raise 'Non TXT queries are not supported yet for this resolver'
        end

        # the `#loadDns().then((dns) => ...)` chain and the 'node:dns resolver is not available' rejection have no counterpart: `resolv` is always loaded

        # @see https://nodejs.org/dist/latest-v20.x/docs/api/dns.html#resolveroptions
        # @see https://manpages.ubuntu.com/manpages/oracular/en/man3/ares_init_options.3.html
        # @see https://docs.ruby-lang.org/en/3.2/Resolv/DNS.html
        # the port of `new dns.Resolver({timeout, tries})`: `options.timeout || -1` leaves the resolver's default per-try
        # timeout in place (`Resolv::DNS::Config::InitialTimeout`, 5 s), `options.tries || 3` the number of rounds
        tries = options[:tries].nil? || options[:tries] == 0 ? 3 : options[:tries]
        per_try_seconds = options[:timeout].nil? || options[:timeout] == 0 ? Resolv::DNS::Config::InitialTimeout : options[:timeout] / 1000.0

        # the `onAbort` listener and its removal have no counterpart: there is no abort signal

        reply = resolve_txt(domain, Array.new(tries, per_try_seconds))

        # the port of the `resolveTxt` callback: `err.code` is the reply's rcode here
        # A missing name (NXDOMAIN/ENOTFOUND) and a name with no records of this type (ENODATA)
        # are both empty answers - same as the DoH resolvers report them; other errors propagate
        case reply.rcode
        when Resolv::DNS::RCode::NXDomain
          return []
        when Resolv::DNS::RCode::NoError
          # NODATA is a NoError reply with no TXT answers: an empty answer below
        else
          raise Resolv::ResolvError, "DNS result has error: rcode #{reply.rcode} for #{domain}"
        end

        # c-ares (`ares_parse_txt_reply`) returns every TXT record of the answer section whatever its owner name, so a CNAME
        # chain is followed to its target's records; the DoH resolvers filter by name instead, as `dns_json.js` does
        records = []
        reply.each_answer do |_n, ttl, data|
          if data.is_a?(Resolv::DNS::Resource::IN::TXT)
            records.push([ttl, data.strings])
          end
        end

        return records.flat_map do |ttl, strings|
          # A TXT record's character-strings concatenate in order with no separator;
          # Resolv delivers them as `strings`, an array of binary chunks, one byte per octet.
          raw = strings.join

          begin
            val = Helpers.utf8_bytes_to_string(raw)
          rescue StandardError => err
            Helpers.log(config, :debug, err)
            # A record whose bytes are not well-formed UTF-8 is ignored as a whole
            next []
          end

          # Resolv reports the TTL of the resource record (`node:dns` reports none); the AD bit is not exposed, so `dnssec` stays nil
          [{
            value: val,
            ttl: ttl,
            dnssec: nil
          }]
        end
      end

      private

      # The port of the `dns.Resolver` + `resolveTxt` primitive: performs the TXT query for the absolute name through
      # `Resolv::DNS::Requester::UnconnectedUDP` and returns the final `Resolv::DNS::Message` reply, whatever its rcode
      # (`resolve` maps the rcode where `node_dns.js` maps `err.code`). `Resolv::DNS#getresources` cannot be used here:
      # it swallows SERVFAIL and timeouts into an empty answer, which `node:dns` reports as `ESERVFAIL`/`ETIMEOUT`. Each
      # try sends the query to every configured nameserver with the try's timeout; a truncated UDP reply repeats the
      # query over TCP through `tcp_exchange`, bounded by the same timeout (Resolv's own `Requester::TCP` connects without
      # one). A timeout of either exchange ends the try (the next nameserver, then the next try); other socket errors
      # propagate. The unit tests replace this method on the instance with `define_singleton_method`.
      #
      # @param domain [String] The domain name to query (the query is made for its absolute form).
      # @param timeouts [Array<Numeric>] The per-try timeouts in seconds, one entry per try.
      #
      # @return [Resolv::DNS::Message] the reply.
      #
      # @raise [Resolv::ResolvError] when every try times out.
      def resolve_txt(domain, timeouts)
        name = Resolv::DNS::Name.create("#{domain}.")
        config = Resolv::DNS::Config.new
        config.lazy_initialize
        nameserver_port = config.nameserver_port
        requester = Resolv::DNS::Requester::UnconnectedUDP.new(*nameserver_port)
        begin
          timeouts.each do |tout|
            nameserver_port.each do |host, port|
              msg = Resolv::DNS::Message.new
              msg.rd = 1
              msg.add_question(name, Resolv::DNS::Resource::IN::TXT)
              sender = requester.sender(msg, name, host, port)
              next if sender.nil? # no socket for the nameserver's address family (as `Resolv::DNS#fetch_resource` skips it)

              begin
                reply, = requester.request(sender, tout)
                if reply.tc == 1
                  # a truncated UDP reply: the same query over TCP, under the same try timeout
                  reply = tcp_exchange(msg, name, host, port, tout)
                end
              rescue Resolv::ResolvTimeout
                next
              end
              return reply
            end
          end
          raise Resolv::ResolvError, "DNS resolv timeout: #{domain}"
        ensure
          requester.close
        end
      end

      # The TCP fallback of `resolve_txt` for a truncated UDP reply: one query over a fresh TCP connection, every phase
      # under the try's timeout `tout` as one deadline - `Socket.tcp(host, port, connect_timeout: tout)`, the
      # length-prefixed message written once the socket is writable, then the 2-byte length and the message read with
      # `wait_readable` and `read_nonblock` until the deadline. The query goes out under a fresh random id (allocated
      # and freed through `Resolv::DNS.allocate_request_id` / `free_request_id`, as Resolv's own senders do), which the
      # reply must carry. A connect timeout, the deadline passing or the peer closing early raise `Resolv::ResolvTimeout`
      # (the try is over, as after a UDP timeout); a reply whose id is not the query's raises `Resolv::ResolvError`;
      # other socket errors propagate. The socket is closed in an `ensure`.
      #
      # @param msg [Resolv::DNS::Message] The query message (sent under a fresh id, see above).
      # @param name [Resolv::DNS::Name] The queried name, for the error message.
      # @param host [String] The nameserver address.
      # @param port [Integer] The nameserver port.
      # @param tout [Numeric] The try's timeout in seconds.
      #
      # @return [Resolv::DNS::Message] the reply.
      #
      # @raise [Resolv::ResolvTimeout] when the exchange does not complete within `tout`.
      # @raise [Resolv::ResolvError] when the reply carries another id.
      def tcp_exchange(msg, name, host, port, tout)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + tout
        begin
          sock = Socket.tcp(host, port, connect_timeout: tout)
        rescue Errno::ETIMEDOUT
          raise Resolv::ResolvTimeout
        end
        begin
          # a fresh random query id, as Resolv's own senders (and c-ares, across its TCP retry) give every query: the
          # Message's default id is a process-wide counter, which the reply check below must not rely on; freed with the socket
          id = Resolv::DNS.allocate_request_id(host, port)
          data = msg.encode
          data[0, 2] = [id].pack('n')
          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          if remaining <= 0 || sock.wait_writable(remaining).nil?
            raise Resolv::ResolvTimeout
          end

          sock.write([data.bytesize].pack('n') + data)

          # the 2-byte length prefix, then the message, read until the deadline
          buffer = ''.b
          expected = 2
          while buffer.bytesize < expected
            remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            if remaining <= 0 || sock.wait_readable(remaining).nil?
              raise Resolv::ResolvTimeout
            end

            chunk = sock.read_nonblock(expected - buffer.bytesize, exception: false)
            if chunk.nil? # EOF: the peer closed before the whole reply arrived
              raise Resolv::ResolvTimeout
            end

            buffer << chunk if chunk != :wait_readable
            if expected == 2 && buffer.bytesize == 2
              expected = 2 + buffer.unpack1('n')
            end
          end

          reply = Resolv::DNS::Message.decode(buffer.byteslice(2, expected - 2))
          if reply.id != id
            raise Resolv::ResolvError, "DNS result has an unexpected id for #{name}"
          end

          return reply
        ensure
          sock.close
          Resolv::DNS.free_request_id(host, port, id) if !id.nil?
        end
      end
    end
  end
end
