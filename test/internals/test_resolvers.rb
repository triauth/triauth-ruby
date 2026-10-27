# frozen_string_literal: true

require_relative '../setup'
require_relative '../stubs/dns_resolver'
require 'json'
require 'resolv'

# Records the options each sub-resolver receives, for fan-out and signal-propagation assertions.
# (A class cannot be defined inside a method body, so it lives here instead of inside the MultiResolver describe.)
class OptionsCapturingStub < DnsResolverStub
  attr_reader :saw_signal_key, :saw_options

  def resolve(domain_name, type, options = {}, config = {})
    @saw_signal_key = options.key?(:signal) # trivially false: the port has no signal key (kept for the split view)
    @saw_options = Triauth::Helpers.object_assign({}, options)
    return super
  end
end

module TestInternals
  def self.resolvers
    # Builds a Response-shaped object with the contract of `Triauth::Helpers.fetch`: `ok` (from `status`), `status`,
    # `headers`, and either `each_chunk` (the port of `body`: a streaming body whose `pull` callable emits chunks
    # through the yielder it receives) or `text` (the port of `text()`: a callable), never both, so the resolver takes
    # the branch the JS test exercises.
    fetch_response = lambda do |status: 200, headers: {}, body: nil, text: nil|
      response = Object.new
      response.define_singleton_method(:ok) { status >= 200 && status < 300 }
      response.define_singleton_method(:status) { status }
      response.define_singleton_method(:headers) { headers }
      response.define_singleton_method(:each_chunk) { |&emit| body.call(emit) } unless body.nil?
      response.define_singleton_method(:text) { text.call } unless text.nil?
      response
    end

    # Response-shaped stub over the text() fallback path, one JSON payload per call.
    text_response = lambda do |payload|
      fetch_response.call(text: -> { JSON.generate(payload) })
    end

    describe 'DNS Resolvers' do
      describe 'Triauth.Resolvers.Base.resolve' do
        it 'rejects as abstract - a subclass must implement it' do
          err = assert_raises(RuntimeError) do
            Triauth::Resolvers::Base.new.resolve('example.com', 'TXT')
          end
          assert_match(/Triauth\.Resolvers\.Base#resolve is abstract and must be implemented by a subclass/, err.message)
        end
      end

      describe 'Triauth.Resolvers.Base.resolveConfig' do
        it 'correctly parses configuration from DNS TXT records' do
          dns_resolver = DnsResolverStub.new(
            { 'config.test': { TXT:
              [
                { value: 'config-key config-value config-option-key[1]=config-option-value-1 config-option-key[2]=config-option-value-2', ttl: 0, dnssec: false },
                { value: 'key BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', ttl: 0, dnssec: false },
                { value: 'utf-8 %5EA%C4%84%5E opt=Z%3D%C5%BB', ttl: 0, dnssec: false },
                { value: 'uri-malformed %5EA%C4%84%5', ttl: 0, dnssec: false }
              ] } }
          )

          records = dns_resolver.resolve_config('config.test')

          assert_equal 'config-key', records[0][:key]
          assert_equal 'config-value', records[0][:value]
          assert_equal 2, records[0][:options].size
          assert_equal 'config-option-value-1', records[0][:options][:'config-option-key[1]']
          assert_equal 'config-option-value-2', records[0][:options][:'config-option-key[2]']

          assert_equal 'key', records[1][:key]
          assert_equal 'BHAILL142prn8rQsHm5ZlMPUFeMc6niVXXIM8biVY3HPjmaw4tfUD-YZ5unkRve1S9P70Mmgk7IBzgVgQPDRnk8', records[1][:value]

          # Values and option values are consumed as published - the record layer never percent-decodes
          assert_equal 'utf-8', records[2][:key]
          assert_equal '%5EA%C4%84%5E', records[2][:value]
          assert_equal 'Z%3D%C5%BB', records[2][:options][:opt]

          # A '%' is an ordinary character at this layer, so a lone trailing '%' parses fine too
          assert_equal 'uri-malformed', records[3][:key]
          assert_equal '%5EA%C4%84%5', records[3][:value]
        end

        it 'extracts options only from the trailing run of whole tokens' do
          dns_resolver = DnsResolverStub.new(
            { 'config.test': { TXT:
              [
                { value: 'name John x-a=1 Doe', ttl: 0, dnssec: false },                  # mid-record option-shaped token is value text
                { value: 'name price a+b=c', ttl: 0, dnssec: false },                     # '=' inside a non-option token never yields a sub-token option
                { value: 'name John x-a=1 x-b=2', ttl: 0, dnssec: false },                # multi-option trailing run
                { value: 'name John x-a=1 x-a=2', ttl: 0, dnssec: false },                # repeated key within the run: last occurrence wins
                { value: 'name x-a=1', ttl: 0, dnssec: false },                           # options-only record has an empty value and is ignored
                { value: 'triauth mode=private auth.example.com', ttl: 0, dnssec: false }, # leading option-shaped token is value text
                { value: 'name John x-a%3D1', ttl: 0, dnssec: false }                     # %3D keeps an option-shaped final token inside the value
              ] } }
          )

          records = dns_resolver.resolve_config('config.test')

          assert_equal 6, records.length

          assert_equal 'John x-a=1 Doe', records[0][:value]
          assert_equal 0, records[0][:options].size

          assert_equal 'price a+b=c', records[1][:value]
          assert_equal 0, records[1][:options].size

          assert_equal 'John', records[2][:value]
          assert_equal 2, records[2][:options].size
          assert_equal '1', records[2][:options][:'x-a']
          assert_equal '2', records[2][:options][:'x-b']

          assert_equal 'John', records[3][:value]
          assert_equal 1, records[3][:options].size
          assert_equal '2', records[3][:options][:'x-a']

          assert_equal 'triauth', records[4][:key]
          assert_equal 'mode=private auth.example.com', records[4][:value]
          assert_equal 0, records[4][:options].size

          # %3D is literal at this layer; the token still has no '=' so it never parses as an option
          assert_equal 'John x-a%3D1', records[5][:value]
          assert_equal 0, records[5][:options].size
        end

        it 'keeps a prototype-poisoning name as an ordinary key of a map without a prototype, for the record family to judge' do
          dns_resolver = DnsResolverStub.new(
            { 'config.test': { TXT:
              [
                { value: 'name John __proto__=evil', ttl: 0, dnssec: false },
                { value: 'name John constructor=evil', ttl: 0, dnssec: false },
                { value: 'name John prototype=evil', ttl: 0, dnssec: false },
                { value: 'name John __proto__=evil x-a=1', ttl: 0, dnssec: false } # sibling options in the same run survive
              ] } }
          )

          records = dns_resolver.resolve_config('config.test')

          assert_equal 4, records.length

          records.each do |record|
            assert_equal 'John', record[:value]

            # The map inherits nothing, so the name is a data key, never a setter or a shadowed member
            # (`Object.getPrototypeOf(record.options) === null` has no counterpart: a Hash has no prototype)
          end

          assert_equal({ __proto__: 'evil' }, records[0][:options])
          assert_equal({ constructor: 'evil' }, records[1][:options])
          assert_equal({ prototype: 'evil' }, records[2][:options])
          assert_equal({ __proto__: 'evil', 'x-a': '1' }, records[3][:options])

          # A spread copy keeps its own prototype: the key travels as data
          # (`Object.getPrototypeOf({...x}) === Object.prototype` has no counterpart; `Object.hasOwn` of the copy is `key?`)
          assert_equal true, records[0][:options].dup.key?(:__proto__)
        end

        it 'keeps the value verbatim between the key and the option run' do
          dns_resolver = DnsResolverStub.new(
            { 'config.test': { TXT:
              [
                'name John   Doe Jr x-a=1',    # inner blank runs of the value survive as published
                "name John  x-a=1 \t x-b=2  ", # blank runs around the options are separators only
                'name John  ',                 # trailing blanks are not part of the value
                'name x-a=1 x-b=2'             # a run of options with no value in front is ignored
              ] } }
          )

          records = dns_resolver.resolve_config('config.test')

          assert_equal 3, records.length

          assert_equal 'John   Doe Jr', records[0][:value]
          assert_equal [[:'x-a', '1']], records[0][:options].to_a

          assert_equal 'John', records[1][:value]
          assert_equal [[:'x-a', '1'], [:'x-b', '2']], records[1][:options].to_a

          assert_equal 'John', records[2][:value]
          assert_equal 0, records[2][:options].size
        end

        it 'ignores a record whose text spans a line, while other blanks separate tokens' do
          dns_resolver = DnsResolverStub.new(
            { 'config.test': { TXT:
              [
                "name John\nx-a=1",
                "name John x-a=1\n",
                "name John\r",
                "name John\tx-a=1"
              ] } }
          )

          records = dns_resolver.resolve_config('config.test')

          assert_equal 1, records.length
          assert_equal 'John', records[0][:value]
          assert_equal [[:'x-a', '1']], records[0][:options].to_a
        end

        it 'parses a DNS-sized record in time linear to its size' do
          # A TXT record tops out at 64 KB. Each parses in a few milliseconds, so the budget is generous.
          dns_resolver = DnsResolverStub.new(
            { 'config.test': { TXT:
              [
                "name x#{' a=b' * 16_000}",     # the longest option run that fits a record
                "name#{' ab' * 16_000}",        # as many value tokens
                "name#{' ' * 32_000}x\n"        # a blank run that ends in a line terminator
              ] } }
          )

          started = Triauth::Helpers.now
          records = dns_resolver.resolve_config('config.test')
          elapsed = Triauth::Helpers.now - started

          assert_equal 2, records.length

          assert_equal 'x', records[0][:value]
          assert_equal [[:a, 'b']], records[0][:options].to_a

          assert_equal "ab#{' ab' * 15_999}", records[1][:value]
          assert_equal 0, records[1][:options].size

          assert elapsed < 500, "parsing three 64 KB records took #{elapsed.round}ms"
        end
      end

      describe 'Triauth.Resolvers.MultiResolver' do
        it 'correctly resolves' do
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 20, dnssec: true }, { value: 'key BBBB', ttl: 20, dnssec: true }, { value: 'key CCCC', ttl: 20, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key BBBB', ttl: 10, dnssec: false }, { value: 'key AAAA', ttl: 10, dnssec: false }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: nil, dnssec: nil }, { value: 'key CCCC', ttl: nil, dnssec: nil }] } })
                                                                 ], { maxFailures: 0 })

          records = multi_resolver.resolve_config('config.test')

          assert_equal 1, records.length
          assert_equal 'key', records[0][:key]
          assert_equal 'AAAA', records[0][:value]
          assert_equal 10, records[0][:ttl]
          assert_equal false, records[0][:dnssec]
        end

        it 'correctly sets the dnssec flag' do
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: false }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: nil }] } })
                                                                 ], { maxFailures: 0 })

          records = multi_resolver.resolve_config('config.test')

          assert_equal false, records[0][:dnssec], 'when any resolver returns false, dnssec must be false'

          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: nil }] } })
                                                                 ], { maxFailures: 0 })

          records = multi_resolver.resolve_config('config.test')

          assert_equal true, records[0][:dnssec], 'undefined value should not affect computed dnssec status'

          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: nil }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: nil }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: nil }] } })
                                                                 ], { maxFailures: 0 })

          records = multi_resolver.resolve_config('config.test')

          assert_nil records[0][:dnssec], 'should be undefined when all resolvers return undefined dnssec'
        end

        it 'computes the dnssec flag independently of resolver order' do
          # A no-opinion resolver listed first must not mask explicit true reports from later resolvers
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: nil }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } })
                                                                 ], { maxFailures: 0 })

          records = multi_resolver.resolve_config('config.test')

          assert_equal true, records[0][:dnssec], 'explicit true reports determine the flag even when the first resolver has no opinion'

          # An explicit false vetoes from any position in the fleet
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: nil }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: false }] } })
                                                                 ], { maxFailures: 0 })

          records = multi_resolver.resolve_config('config.test')

          assert_equal false, records[0][:dnssec], 'an explicit false vetoes regardless of resolver order'
        end

        it 'keeps a TTL of 0 in the min-aggregation, independently of resolver order' do
          # TTL 0 means immediate expiry (e.g., revocation); it must win the min
          # against larger TTLs from other resolvers, from any position in the fleet
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 0, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 300, dnssec: true }] } })
                                                                 ], { maxFailures: 0 })

          records = multi_resolver.resolve('config.test', 'TXT')

          assert_equal 0, records[0][:ttl], 'a TTL of 0 reported first must not be overwritten by a larger TTL'

          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 300, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 0, dnssec: true }] } })
                                                                 ], { maxFailures: 0 })

          records = multi_resolver.resolve('config.test', 'TXT')

          assert_equal 0, records[0][:ttl], 'a TTL of 0 reported later must win the min against a larger TTL'
        end

        # Records the options each sub-resolver receives, for fan-out and signal-propagation assertions.
        # (`OptionsCapturingStub` sits at the top of this file: a class cannot be defined inside a method body)

        it 'fans out per-call and constructor options to sub-resolvers, keeping its own consumed keys' do
          stub = OptionsCapturingStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } })
          multi_resolver = Triauth::Resolvers::MultiResolver.new([stub], { maxFailures: 0, skipPadding: true })

          records = multi_resolver.resolve('config.test', 'TXT', { retries: 2, normalizeTxtRecords: true, timeout: 5000 })

          assert_equal 'key AAAA', records[0][:value]
          assert_equal 2, stub.saw_options[:retries], 'per-call sub-resolver options must cross the fan-out boundary'
          assert_equal true, stub.saw_options[:normalizeTxtRecords], 'per-call TXT flags must cross the fan-out boundary'
          assert_equal true, stub.saw_options[:skipPadding], 'constructor-level options fan out through the merge'
          assert_equal false, stub.saw_options.key?(:maxFailures), 'maxFailures is consumed at the MultiResolver layer'
          assert_equal false, stub.saw_options.key?(:timeout), 'timeout is consumed at the MultiResolver layer'
        end

        # 'attaches an abort signal to sub-resolvers when AbortController is available' is not ported: there is no AbortSignal

        it 'tolerates sub-resolver failures within the maxFailures budget' do
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { _error: 'boom' } })
                                                                 ], { maxFailures: 1 })

          records = multi_resolver.resolve_config('config.test')

          assert_equal 1, records.length
          assert_equal 'AAAA', records[0][:value]
        end

        it 'rejects when failures exceed maxFailures' do
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } }),
                                                                   DnsResolverStub.new({ 'config.test': { _error: 'boom' } })
                                                                 ], { maxFailures: 0 })

          # the JS rejection value (an Array of the reasons) travels in `ResolutionError#reasons`
          err = assert_raises(Triauth::Resolvers::MultiResolver::ResolutionError) do
            multi_resolver.resolve('config.test', 'TXT')
          end
          assert_kind_of Array, err.reasons
          assert_equal 1, err.reasons.length
          assert_match(/boom/, err.reasons[0].message)
        end

        it 'rejects when every resolver fails, regardless of the maxFailures budget' do
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { _error: 'boom one' } }),
                                                                   DnsResolverStub.new({ 'config.test': { _error: 'boom two' } })
                                                                 ], { maxFailures: 5 })

          err = assert_raises(Triauth::Resolvers::MultiResolver::ResolutionError) do
            multi_resolver.resolve('config.test', 'TXT')
          end
          assert_kind_of Array, err.reasons
          assert_equal 2, err.reasons.length
        end

        it 'rejects with a timeout when resolvers stall (AbortController present)' do
          # A stub that never settles within the deadline: its thread is left to finish on its own (no timers involved).
          stalling = DnsResolverStub.new
          stalling.define_singleton_method(:resolve) { |*| sleep 5 }

          multi_resolver = Triauth::Resolvers::MultiResolver.new([stalling], { maxFailures: 0, timeout: 50 })

          started = Triauth::Helpers.now
          err = assert_raises(RuntimeError) { multi_resolver.resolve('config.test', 'TXT') }
          assert_match(/MultiResolver timeout/, err.message)
          assert_operator Triauth::Helpers.now - started, :<, 1000, 'the deadline must end the call, not the stalling resolver'
        end

        it 'clears the timeout when resolution completes in time' do
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   DnsResolverStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } })
                                                                 ], { maxFailures: 0, timeout: 5000 })

          records = multi_resolver.resolve_config('config.test')

          assert_equal 'AAAA', records[0][:value]
        end

        describe 'without AbortController' do
          # Simulates a runtime that lacks AbortController (e.g. nginx/njs): resolution must
          # proceed, options.timeout is ignored, and no signal may reach the sub-resolvers.
          # (the port never has an AbortController: the `globalThis.AbortController` save/restore has no counterpart)

          it 'resolves and passes no signal key to sub-resolvers' do
            # `globalThis.AbortController = undefined` has no counterpart: the runtime never has it

            stub = OptionsCapturingStub.new({ 'config.test': { TXT: [{ value: 'key AAAA', ttl: 10, dnssec: true }] } })
            # timeout is set on purpose: it must be ignored without AbortController
            multi_resolver = Triauth::Resolvers::MultiResolver.new([stub], { maxFailures: 0, timeout: 1000 })

            records = multi_resolver.resolve_config('config.test')

            assert_equal 1, records.length
            assert_equal 'AAAA', records[0][:value]
            assert_equal false, stub.saw_signal_key, 'no AbortSignal should be attached when AbortController is unavailable'
          end
        end
      end

      describe 'TXT character-string concatenation' do
        # A TXT record's RDATA is one or more 255-octet character-strings whose contents concatenate
        # in order with no separator. Each resolver path delivers that logical content.

        before { @original_fetch = Triauth::Helpers.method(:fetch) }
        after { Triauth::Helpers.define_singleton_method(:fetch, @original_fetch) }

        # Response-shaped stub whose body streams one JSON payload.
        stub_json_fetch = lambda do |payload|
          bytes = JSON.generate(payload).b
          ->(_url, _opts, &blk) { blk.call(fetch_response.call(body: ->(emit) { emit.call(bytes) })) }
        end

        # Response-shaped stub streaming raw bytes, chunk_size bytes at a time.
        stub_bytes_fetch = lambda do |bytes, chunk_size = bytes.bytesize|
          lambda do |_url, _opts, &blk|
            body = lambda do |emit|
              offset = 0
              while offset < bytes.bytesize
                emit.call(bytes.byteslice(offset, chunk_size))
                offset += chunk_size
              end
            end
            blk.call(fetch_response.call(body: body))
          end
        end

        it_node 'NodeDns joins a multi-chunk TXT answer with no separator' do
          node_dns = Triauth::Resolvers::SystemDns.new

          # Resolv delivers each TXT answer as `strings`, an array of character-string chunks
          node_dns.define_singleton_method(:resolve_txt) do |_domain, _timeouts|
            msg = Resolv::DNS::Message.new
            msg.rcode = Resolv::DNS::RCode::NoError
            msg.add_answer(Resolv::DNS::Name.create('config.test.'), 300, Resolv::DNS::Resource::IN::TXT.new('key part1', 'part2'))
            msg.add_answer(Resolv::DNS::Name.create('config.test.'), 300, Resolv::DNS::Resource::IN::TXT.new('single'))
            msg
          end

          records = node_dns.resolve('config.test', 'TXT')

          assert_equal 2, records.length
          assert_equal 'key part1part2', records[0][:value]
          assert_equal 'single', records[1][:value]
          # port-only assertions: the TTL of the resource record is reported and the DNSSEC status is not
          assert_equal 300, records[0][:ttl]
          assert_nil records[0][:dnssec]
        end

        it_node 'NodeDns resolves an empty answer for NXDOMAIN and NODATA alike, and propagates other errors' do
          node_dns = Triauth::Resolvers::SystemDns.new

          # the port of `stubDnsError(code)`: a reply carrying the rcode (the `err.code` of node:dns)
          stub_dns_reply = lambda do |rcode|
            lambda do |_domain, _timeouts|
              msg = Resolv::DNS::Message.new
              msg.rcode = rcode
              msg
            end
          end

          # A missing name and a name with no TXT records are both empty answers,
          # matching how the DoH resolvers report the same DNS states
          node_dns.define_singleton_method(:resolve_txt, &stub_dns_reply.call(Resolv::DNS::RCode::NXDomain))
          assert_equal [], node_dns.resolve('config.test', 'TXT')

          node_dns.define_singleton_method(:resolve_txt, &stub_dns_reply.call(Resolv::DNS::RCode::NoError)) # NODATA: a NoError reply with no answers
          assert_equal [], node_dns.resolve('config.test', 'TXT')

          node_dns.define_singleton_method(:resolve_txt) { |_domain, _timeouts| raise Resolv::ResolvError, 'DNS resolv timeout: config.test' } # the port of ETIMEOUT
          err = assert_raises(Resolv::ResolvError) { node_dns.resolve('config.test', 'TXT') }
          assert_match(/timeout/, err.message)

          # port-only assertion: any other rcode (SERVFAIL here) propagates too, as `ESERVFAIL` does
          node_dns.define_singleton_method(:resolve_txt, &stub_dns_reply.call(Resolv::DNS::RCode::ServFail))
          err = assert_raises(Resolv::ResolvError) { node_dns.resolve('config.test', 'TXT') }
          assert_match(/rcode 2/, err.message)
        end

        it_node 'NodeDns rejects instead of hanging when the resolver cannot be constructed (e.g., out-of-range options)' do
          node_dns = Triauth::Resolvers::SystemDns.new

          node_dns.define_singleton_method(:resolve_txt) { |_domain, _timeouts| raise 'ERR_OUT_OF_RANGE' }

          err = assert_raises(RuntimeError) { node_dns.resolve('config.test', 'TXT') }
          assert_match(/ERR_OUT_OF_RANGE/, err.message)
        end

        it 'DnsJson.normalizeTxtData concatenates presentation-form character-strings' do
          assert_equal 'abcdef', Triauth::Resolvers::DnsJson.normalize_txt_data('"abc" "def"')
          assert_equal 'abc', Triauth::Resolvers::DnsJson.normalize_txt_data('"abc"')
          assert_equal 'abc', Triauth::Resolvers::DnsJson.normalize_txt_data('"a" "b" "c"')
        end

        it 'DnsJson.normalizeTxtData decodes escaped quotes and backslashes as literals' do
          assert_equal 'a"bc\\d', Triauth::Resolvers::DnsJson.normalize_txt_data('"a\\"b" "c\\\\d"')
        end

        it 'DnsJson.normalizeTxtData keeps escapes verbatim with keepEscapes, for the single-pass decode stage' do
          assert_equal 'a\\"bc\\\\d', Triauth::Resolvers::DnsJson.normalize_txt_data('"a\\"b" "c\\\\d"', true)
        end

        it 'DnsJson.normalizeTxtData returns logical-form and malformed data unchanged' do
          assert_equal 'key plain-value', Triauth::Resolvers::DnsJson.normalize_txt_data('key plain-value')
          assert_equal '"unterminated', Triauth::Resolvers::DnsJson.normalize_txt_data('"unterminated')
          assert_equal '"a"x"b"', Triauth::Resolvers::DnsJson.normalize_txt_data('"a"x"b"')
        end

        it 'Cloudflare yields concatenated content for presentation-form answers, with decimal escapes decoding to utf-8' do
          payload = {
            Status: 0, AD: true,
            Answer: [
              { name: 'config.test', type: 16, TTL: 30, data: '"key part1" "part2"' },
              # a decimal escape pair (RFC 1035 presentation format; Ą = bytes 196 132) split across
              # the character-string boundary decodes after concatenation
              { name: 'config.test', type: 16, TTL: 30, data: '"utf-8 A\\196" "\\132B"' }
            ]
          }
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 'key part1part2', records[0][:value]
          assert_equal 'utf-8 AĄB', records[1][:value]
        end

        it 'DnsSb yields concatenated content for presentation-form answers' do
          payload = {
            Status: 0, AD: true,
            Answer: [
              { name: 'config.test', type: 16, TTL: 30, data: '"key part1" "part2"' }
            ]
          }
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))

          resolver = Triauth::Resolvers::DnsSb.new({ skipPadding: true, retries: 0 })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 'key part1part2', records[0][:value]
        end

        it 'Google passes logical-form answers through unchanged' do
          payload = {
            Status: 0, AD: true,
            Answer: [
              { name: 'config.test', type: 16, TTL: 30, data: 'key part1part2' }
            ]
          }
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))

          resolver = Triauth::Resolvers::Google.new({ skipPadding: true, retries: 0 })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 'key part1part2', records[0][:value]
        end

        it 'DnsJson resolves a large RRset (150 answers)' do
          payload = {
            Status: 0, AD: true,
            Answer: Array.new(150) { |i| { name: 'config.test', type: 16, TTL: 30, data: "key device#{i}[1/1]:value#{i}" } }
          }
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))

          resolver = Triauth::Resolvers::DnsJson.new('https://doh.test/dns-query', { skipPadding: true, retries: 0 })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 150, records.length
          assert_equal 'key device149[1/1]:value149', records[149][:value]
        end

        it 'DnsJson honors per-call normalizeTxtRecords/decodeTxtRecords overrides in both directions' do
          payload = {
            Status: 0, AD: true,
            Answer: [
              { name: 'config.test', type: 16, TTL: 30, data: '"key A\\196" "\\132B"' }
            ]
          }

          # Flags absent at construction, enabled per-call: presentation form normalizes and decodes
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))
          bare = Triauth::Resolvers::DnsJson.new('https://doh.test/dns-query', { skipPadding: true, retries: 0 })
          records = bare.resolve('config.test', 'TXT', { normalizeTxtRecords: true, decodeTxtRecords: true })
          assert_equal 'key AĄB', records[0][:value]

          # Flags set at construction (Cloudflare), disabled per-call: data passes through verbatim
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))
          cloudflare = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          records = cloudflare.resolve('config.test', 'TXT', { normalizeTxtRecords: false, decodeTxtRecords: false })
          assert_equal '"key A\\196" "\\132B"', records[0][:value]
        end

        it 'Cloudflare decodes same-level presentation escapes in one pass (escaped backslash before digits stays literal)' do
          payload = {
            Status: 0, AD: true,
            Answer: [
              # logical content `literal \123`: presentation escapes the backslash as \\ ,
              # which must not merge with the digits into a \DDD escape
              { name: 'config.test', type: 16, TTL: 30, data: '"literal \\\\123"' },
              { name: 'config.test', type: 16, TTL: 30, data: '"say \\"hi\\""' }
            ]
          }
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 'literal \\123', records[0][:value]
          assert_equal 'say "hi"', records[1][:value]
        end

        it 'Cloudflare skips records with malformed decimal escapes instead of guessing, keeping siblings' do
          payload = {
            Status: 0, AD: true,
            Answer: [
              # \321 would wrap to 65 ('A') under a mod-256 reading; the record rejects instead
              { name: 'config.test', type: 16, TTL: 30, data: '"over \\321"' },
              # a \DDD escape is exactly three digits; shorter runs reject
              { name: 'config.test', type: 16, TTL: 30, data: '"short \\04"' },
              { name: 'config.test', type: 16, TTL: 30, data: '"key good"' }
            ]
          }
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 1, records.length
          assert_equal 'key good', records[0][:value]
        end

        it 'Cloudflare skips a record carrying raw non-octet characters under the escape contract, keeping siblings' do
          payload = {
            Status: 0, AD: true,
            Answer: [
              # decodeTxtRecords means one-char-per-octet content (printable ASCII + \DDD escapes);
              # raw Ą (U+0104) would wrap mod-256 to the control char U+0004 — the record rejects instead
              { name: 'config.test', type: 16, TTL: 30, data: '"ZoĄ \\196\\132"' },
              { name: 'config.test', type: 16, TTL: 30, data: '"key good"' }
            ]
          }
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 1, records.length
          assert_equal 'key good', records[0][:value]
        end

        it 'Cloudflare skips a record whose decimal escapes decode to ill-formed UTF-8, keeping its siblings' do
          payload = {
            Status: 0, AD: true,
            Answer: [
              # \233 is the lone latin-1 'é' octet (0xE9) — not well-formed UTF-8 on its own,
              # so the record is ignored as a whole (a record value must be well-formed UTF-8)
              { name: 'config.test', type: 16, TTL: 30, data: '"bad \\233"' },
              { name: 'config.test', type: 16, TTL: 30, data: '"key good"' }
            ]
          }
          Triauth::Helpers.define_singleton_method(:fetch, &stub_json_fetch.call(payload))

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 1, records.length
          assert_equal 'key good', records[0][:value]
        end

        it_node 'NodeDns reinterprets one-char-per-octet chunks as UTF-8, dropping records with ill-formed bytes' do
          node_dns = Triauth::Resolvers::SystemDns.new

          node_dns.define_singleton_method(:resolve_txt) do |_domain, _timeouts|
            msg = Resolv::DNS::Message.new
            msg.rcode = Resolv::DNS::RCode::NoError
            # C3 A9 split across the character-string boundary is UTF-8 'é' after concatenation;
            # the record carrying a lone E9 octet is not well-formed UTF-8
            msg.add_answer(Resolv::DNS::Name.create('config.test.'), 300, Resolv::DNS::Resource::IN::TXT.new("name Zo\xC3".b, "\xA9".b))
            msg.add_answer(Resolv::DNS::Name.create('config.test.'), 300, Resolv::DNS::Resource::IN::TXT.new("name Zo\xE9".b))
            msg
          end

          records = node_dns.resolve('config.test', 'TXT')

          assert_equal 1, records.length
          assert_equal 'name Zoé', records[0][:value]
        end

        it 'DnsJson rejects a response body that is not well-formed UTF-8' do
          # A valid JSON skeleton with a raw 0xE9 octet inside a string value — the body is
          # refused as a whole (a transport-level failure, like a bad status code)
          head = '{"Status":0,"AD":true,"Answer":[{"name":"config.test","type":16,"TTL":30,"data":"key '.b
          tail = '"}]}'.b
          Triauth::Helpers.define_singleton_method(:fetch, &stub_bytes_fetch.call(head + "\xE9".b + tail))

          resolver = Triauth::Resolvers::Google.new({ skipPadding: true, retries: 0 })

          assert_raises(StandardError) { resolver.resolve('config.test', 'TXT') }
        end

        it 'DnsJson decodes multi-byte characters split across stream chunks' do
          payload = JSON.generate({
                                    Status: 0, AD: true,
                                    Answer: [{ name: 'config.test', type: 16, TTL: 30, data: 'key Zoé' }]
                                  })

          # One byte per chunk, so the é's C3 A9 pair always spans a chunk boundary
          Triauth::Helpers.define_singleton_method(:fetch, &stub_bytes_fetch.call(payload.b, 1))

          resolver = Triauth::Resolvers::Google.new({ skipPadding: true, retries: 0 })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 'key Zoé', records[0][:value]
        end
      end

      describe 'Triauth.Resolvers.DnsJson retry behavior' do
        # 'treats an abort from the caller signal as terminal' is not ported: there is no caller signal

        it 'carries the per-call config across a DNS-status retry (the retried attempt still logs)' do
          calls = 0
          answer = {
            Status: 0, AD: true, Answer: [
              { name: 'config.test', type: 16, TTL: 30, data: 'bad \\999' }, # invalid \DDD escape — logged and skipped
              { name: 'config.test', type: 16, TTL: 30, data: 'key good' }
            ]
          }
          fetch_stub = lambda do |_url, _opts, &blk|
            calls += 1
            blk.call(calls == 1 ? text_response.call({ Status: 2 }) : text_response.call(answer)) # SERVFAIL first — triggers the status-retry path
          end

          logs = []
          logger = Object.new
          logger.define_singleton_method(:debug) { |msg, *| logs.push(msg.to_s) }

          resolver = Triauth::Resolvers::DnsJson.new('https://doh.test/dns-query', { skipPadding: true })
          records = resolver.resolve('config.test', 'TXT',
                                     { retries: 1, retryDelay: 0, decodeTxtRecords: true, fetch: fetch_stub }, { logger: logger })

          assert_equal 2, calls
          assert_equal 1, records.length
          assert_equal 'key good', records[0][:value]
          assert logs.any? { |m| m.include?('DNS TXT record could not be decoded') },
                 'the retried attempt must log through the caller-provided config'
        end

        it 'rejects an exhausted DNS-status retry with a real Error naming the status' do
          resolver = Triauth::Resolvers::DnsJson.new('https://doh.test/dns-query', { skipPadding: true })

          err = assert_raises(RuntimeError) do # `err instanceof Error`: a real exception, not a string rejection
            resolver.resolve('config.test', 'TXT', { retries: 0, fetch: ->(_url, _opts, &blk) { blk.call(text_response.call({ Status: 2 })) } })
          end
          assert_match(/DNS status 2/, err.message)
        end
      end

      describe 'Triauth.Resolvers.DnsJson answer filters and transport retries' do
        # Answer shapes a real zone never produces: the per-answer filters and the transport-error
        # retry are pinned here, while the published test zone covers what real providers return.
        answering = lambda do |payload|
          Triauth::Resolvers::DnsJson.new('https://doh.test/dns-query',
                                          { skipPadding: true, fetch: ->(_url, _opts, &blk) { blk.call(text_response.call(payload)) } })
        end

        it 'keeps only well-formed answers for the queried name and type' do
          records = answering.call({ Status: 0, AD: true, Answer: [
                                     { name: 'config.test',  type: 5,  TTL: 30,  data: 'target.test.' },  # a CNAME entry at the queried name: wrong type
                                     { name: 'target.test',  type: 16, TTL: 30,  data: 'key target' },    # the alias target's own TXT: wrong name
                                     { name: 'config.test.', type: 16, TTL: 30,  data: 'key absolute' },  # the queried name in absolute form: kept
                                     { name: 'config.test',  type: 16, TTL: 30,  data: 42 },              # data must be a string
                                     { name: 'config.test',  type: 16, TTL: -1,  data: 'key negative' },  # TTL must be a non-negative integer
                                     { name: 'config.test',  type: 16, TTL: '30', data: 'key string TTL' },
                                     'junk',                                                           # port-only shape: a non-object answer is skipped (`'junk'['name']` is undefined in JS)
                                     { name: 'config.test',  type: 16, TTL: 30,  data: 'key good' }
                                   ] }).resolve('config.test', 'TXT')

          assert_equal ['key absolute', 'key good'], records.map { |r| r[:value] }.sort
        end

        it 'compares the owner name without regard to ASCII case, as DNS does (RFC 4343)' do
          records = answering.call({ Status: 0, AD: true, Answer: [
                                     { name: '_4gibdu53b3._at.private.test.', type: 16, TTL: 30, data: 'key lowercase absolute' },  # the queried private label, lowercased by the server
                                     { name: '_4GIBDU53B3._AT.PRIVATE.TEST',  type: 16, TTL: 30, data: 'key uppercase' },
                                     { name: '_4GIBDU53B4._at.private.test',  type: 16, TTL: 30, data: 'key other label' },         # another name: dropped
                                     { name: 42,                              type: 16, TTL: 30, data: 'key non-string name' }      # a name must be a string
                                   ] }).resolve('_4GIBDU53B3._at.private.test', 'TXT')

          assert_equal ['key lowercase absolute', 'key uppercase'], records.map { |r| r[:value] }.sort
        end

        it 'keeps a record in the MultiResolver intersection when one resolver spells the owner name in another case' do
          spelling = ->(name) { answering.call({ Status: 0, AD: true, Answer: [{ name: name, type: 16, TTL: 30, data: 'key private' }] }) }
          multi_resolver = Triauth::Resolvers::MultiResolver.new([
                                                                   spelling.call('_4gibdu53b3._at.private.test.'),
                                                                   spelling.call('_4GIBDU53B3._at.private.test')
                                                                 ], { maxFailures: 0 })

          records = multi_resolver.resolve('_4GIBDU53B3._at.private.test', 'TXT')

          assert_equal(['key private'], records.map { |r| r[:value] })
        end

        # port-only (hazards pass): `for (const a of (json['Answer'] || []))` iterates nothing for the JS falsy values and
        # the characters of a String (no answer among them), and throws for a Hash or any other non-iterable value, which
        # the retry path surfaces once the budget is spent
        it 'treats a falsy or String Answer as an empty answer and a Hash Answer as not iterable, as for...of over json.Answer || [] does' do
          [0, '', 'abc', nil, false].each do |shape|
            assert_equal [], answering.call({ Status: 0, AD: true, Answer: shape }).resolve('config.test', 'TXT'), shape.inspect
          end

          [{}, { a: 1 }, true, 5].each do |shape| # (a fraction such as 1.5 is a JSON validation error ahead of the loop since beta.4, on both sides)
            err = assert_raises(TypeError, shape.inspect) do
              answering.call({ Status: 0, AD: true, Answer: shape }).resolve('config.test', 'TXT')
            end
            assert_equal "json['Answer'] is not iterable", err.message
          end

          calls = 0
          resolver = Triauth::Resolvers::DnsJson.new('https://doh.test/dns-query', {
                                                       skipPadding: true, fetch: lambda do |_url, _opts, &blk|
                                                                                   calls += 1
                                                                                   blk.call(text_response.call({ Status: 0, AD: true, Answer: {} }))
                                                                                 end
                                                     })

          assert_raises(TypeError) { resolver.resolve('config.test', 'TXT', { retries: 1, retryDelay: 0 }) }
          assert_equal 2, calls
        end

        it 'drops every answer of a response whose AD flag is not a boolean' do
          records = answering.call({ Status: 0, AD: 'true', Answer: [
                                     { name: 'config.test', type: 16, TTL: 30, data: 'key good' }
                                   ] }).resolve('config.test', 'TXT')

          assert_equal [], records
        end

        it 'resolves an empty answer for NXDOMAIN (Status 3) without spending retries' do
          calls = 0
          resolver = Triauth::Resolvers::DnsJson.new('https://doh.test/dns-query', {
                                                       skipPadding: true, fetch: lambda do |_url, _opts, &blk|
                                                                                   calls += 1
                                                                                   blk.call(text_response.call({ Status: 3 }))
                                                                                 end
                                                     })

          assert_equal [], resolver.resolve('missing.test', 'TXT', { retries: 2 })
          assert_equal 1, calls
        end

        it 'retries a transport failure once and resolves on the next attempt' do
          calls = 0
          fetch_stub = lambda do |_url, _opts, &blk|
            calls += 1
            if calls == 1
              raise TypeError, 'fetch failed'
            end

            blk.call(text_response.call({ Status: 0, AD: true, Answer: [{ name: 'config.test', type: 16, TTL: 30, data: 'key good' }] }))
          end
          resolver = Triauth::Resolvers::DnsJson.new('https://doh.test/dns-query', { skipPadding: true })

          records = resolver.resolve('config.test', 'TXT', { retries: 1, retryDelay: 0, fetch: fetch_stub })
          assert_equal 'key good', records[0][:value]
          assert_equal 2, calls
        end

        it 'rejects a transport failure outright once no retry is left' do
          calls = 0
          resolver = Triauth::Resolvers::DnsJson.new('https://doh.test/dns-query', { skipPadding: true })
          fetch_stub = lambda do |_url, _opts, &_blk|
            calls += 1
            raise TypeError, 'fetch failed'
          end

          err = assert_raises(TypeError) do
            resolver.resolve('config.test', 'TXT', { retries: 0, fetch: fetch_stub })
          end
          assert_equal 'fetch failed', err.message
          assert_equal 1, calls
        end

        # 'NodeDns cancels the in-flight query on abort, and detaches its listener once the query settles' is not ported: there is no AbortSignal
      end

      describe 'Triauth.Resolvers.DnsJson body limits' do
        limit = 256 * 1024
        chunk = 64 * 1024

        before { @original_fetch = Triauth::Helpers.method(:fetch) }
        after { Triauth::Helpers.define_singleton_method(:fetch, @original_fetch) }

        # Build a Response-shaped object whose body stream is driven by `stream_source`, the port of `pull(c)`: it
        # receives the yielder and emits chunks through it (`c.enqueue(x)` is `emit.call(x)`, `c.close()` is returning).
        # Aborting is the resolver raising from inside its `each_chunk` block, which unwinds through the stream source.
        make_stub_fetch = lambda do |status:, content_length:, stream_source:|
          lambda do |_url, _opts, &blk|
            headers = content_length.nil? ? {} : { 'content-length' => content_length }
            blk.call(fetch_response.call(status: status, headers: headers, body: stream_source))
          end
        end

        it 'rejects without reading body when Content-Length declares over-limit size' do
          pulls = 0
          Triauth::Helpers.define_singleton_method(:fetch, &make_stub_fetch.call(
            status: 200,
            content_length: (limit + 1024).to_s,
            stream_source: ->(_emit) { pulls += 1 }
          ))

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          err = assert_raises(StandardError) { resolver.resolve('example.com', 'TXT') }
          assert_match(/Content-Length/, err.message)
          assert_equal 0, pulls, 'body must not be pulled when Content-Length exceeds limit'
        end

        it 'aborts the request when streamed bytes exceed the size limit' do
          bytes_enqueued = 0
          signal_seen = nil
          Triauth::Helpers.define_singleton_method(:fetch) do |_url, _opts, &blk|
            body = lambda do |emit|
              loop do
                bytes_enqueued += chunk
                emit.call("\x00".b * chunk)
              end
            rescue StandardError => err
              signal_seen = err # the port of `signalSeen.aborted`: the stub observes the raise that aborts the body read
              raise
            end
            blk.call(fetch_response.call(body: body))
          end

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          start = Triauth::Helpers.date_now
          err = assert_raises(StandardError) { resolver.resolve('example.com', 'TXT') }
          elapsed = Triauth::Helpers.date_now - start

          assert_equal 'DoH response exceeds size limit', err.message
          assert elapsed < 5000, "expected fast abort, took #{elapsed}ms"
          assert signal_seen, 'request signal should be aborted'
          # Resolver accepts up to 4 x 64KB = 256KB (= LIMIT, not >), then rejects the 5th chunk.
          # Allow some slack in case the stream pull is called speculatively beyond what's read.
          assert bytes_enqueued <= limit + (2 * chunk),
                 "bytes enqueued (#{bytes_enqueued}) exceeded LIMIT + 2*CHUNK (#{limit + (2 * chunk)})"
        end

        it 'rejects non-2xx responses before reading the body' do
          pulls = 0
          Triauth::Helpers.define_singleton_method(:fetch, &make_stub_fetch.call(
            status: 500,
            content_length: nil,
            stream_source: ->(_emit) { pulls += 1 }
          ))

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          err = assert_raises(StandardError) { resolver.resolve('example.com', 'TXT') }
          assert_match(/500/, err.message)
          assert_equal 0, pulls, 'body must not be pulled when status is non-2xx'
        end

        it 'respects options.timeout when the body is slow (timeout stays armed past headers)' do
          # The silent server of the JS test is cut by the transport's read timeout here (also `options[:timeout]`, pinned by
          # the port-only `fetch` tests of test_helpers.rb), so this stub drips one byte every 30 ms instead: only the
          # resolver's deadline, armed across the body read, can end a dripping body
          dripping = lambda do |emit|
            loop do
              sleep 0.03
              emit.call('x'.b)
            end
          end
          Triauth::Helpers.define_singleton_method(:fetch, &make_stub_fetch.call(
            status: 200,
            content_length: nil,
            stream_source: dripping
          ))

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0 })
          start = Triauth::Helpers.date_now
          err = assert_raises(StandardError) { resolver.resolve('example.com', 'TXT', { timeout: 100 }) }
          elapsed = Triauth::Helpers.date_now - start

          assert_equal 'Resolver timeout', err.message
          assert elapsed >= 90, "expected to wait for timeout, only took #{elapsed}ms"
          assert elapsed < 1000, "timeout should fire within ~100ms, took #{elapsed}ms"
        end
      end

      describe 'Triauth.Resolvers.DnsJson constrained fetch (injected client, no AbortController/stream)' do
        # Simulates a runtime where fetch is injected (not a global), the response
        # exposes only text() (no ReadableStream body), and AbortController is absent.

        before { @original_fetch = Triauth::Helpers.method(:fetch) }
        after { Triauth::Helpers.define_singleton_method(:fetch, @original_fetch) }
        # the `globalThis.AbortController` save/restore has no counterpart: there is no AbortController here

        # A text()-only Response
        text_only_response = lambda do |payload, status: 200, content_length: nil|
          fetch_response.call(
            status: status,
            headers: content_length.nil? ? {} : { 'content-length' => content_length },
            text: -> { payload.is_a?(String) ? payload : JSON.generate(payload) }
          )
        end

        it 'resolves through an injected fetch with a text()-only response and no AbortController' do
          Triauth::Helpers.define_singleton_method(:fetch) { |*| raise 'global fetch must not be used' }

          saw_url = nil
          saw_had_signal_key = true
          injected_fetch = lambda do |url, opts, &blk|
            saw_url = url
            saw_had_signal_key = opts.key?(:signal) # must be omitted entirely, not set to undefined (trivially true here: the port has no signal key; kept for the split view)
            blk.call(text_only_response.call({
                                               Status: 0, AD: true,
                                               Answer: [{ name: 'config.test', type: 16, TTL: 30, data: '"key part1" "part2"' }]
                                             }))
          end

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0, fetch: injected_fetch })
          records = resolver.resolve('config.test', 'TXT')

          assert_equal 'key part1part2', records[0][:value]
          assert_equal true, records[0][:dnssec]
          assert saw_url.start_with?('https://cloudflare-dns.com/dns-query?name=config.test')
          assert_equal false, saw_had_signal_key, 'no AbortSignal should be attached when AbortController is unavailable'
        end

        it 'enforces the size cap on the text() fallback path' do
          huge = 'x' * ((256 * 1024) + 1)
          injected_fetch = ->(_url, _opts, &blk) { blk.call(text_only_response.call("{\"padding\":\"#{huge}\"}")) }

          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0, fetch: injected_fetch })
          err = assert_raises(StandardError) { resolver.resolve('example.com', 'TXT') }
          assert_match(/size limit/, err.message)
        end

        it 'honors the Content-Length pre-check without an AbortController' do
          text_read = false
          injected_fetch = lambda do |_url, _opts, &blk|
            blk.call(fetch_response.call(
                       headers: { 'content-length' => ((256 * 1024) + 1024).to_s },
                       text: lambda do
                               text_read = true
                               '{}'
                             end
                     ))
          end
          resolver = Triauth::Resolvers::Cloudflare.new({ skipPadding: true, retries: 0, fetch: injected_fetch })
          err = assert_raises(StandardError) { resolver.resolve('example.com', 'TXT') }
          assert_match(/Content-Length/, err.message)
          assert_equal false, text_read, 'body must not be read when Content-Length exceeds the limit'
        end

        # 'rejects when no fetch implementation is available' is not ported: the branch is dropped, the default transport always exists
      end

      describe 'Triauth.Resolvers.SystemDns (port-only)' do
        # The test below exists only in the port: it pins the try timeout of the TCP
        # fallback of `resolve_txt` (`tcp_exchange`), which Resolv's own `Requester::TCP` leaves unbounded.

        it 'gives up on the TCP fallback within the try timeout when the nameserver accepts and never answers' do
          server = TCPServer.new('127.0.0.1', 0)
          port = server.addr[1]
          thread = Thread.new do
            sock = server.accept
            begin
              sock.readpartial(1024) # the query arrives in full; no answer is ever sent
              sock.wait_readable(3)  # the client gives up first and closes
            ensure
              sock.close
            end
          end
          thread.report_on_exception = false

          node_dns = Triauth::Resolvers::SystemDns.new
          name = Resolv::DNS::Name.create('config.test.')
          msg = Resolv::DNS::Message.new
          msg.rd = 1
          msg.add_question(name, Resolv::DNS::Resource::IN::TXT)

          started = Triauth::Helpers.now
          assert_raises(Resolv::ResolvTimeout) { node_dns.send(:tcp_exchange, msg, name, '127.0.0.1', port, 0.3) }
          elapsed = Triauth::Helpers.now - started
          thread.join(5)
          server.close

          assert_operator elapsed, :>=, 200
          assert_operator elapsed, :<, 1500
        end

        it 'returns every TXT record of the answer section, so a CNAME alias resolves to the records of its target (as node:dns does)' do
          node_dns = Triauth::Resolvers::SystemDns.new

          # the reply of a recursive resolver for an alias: the CNAME, then the target's TXT (owned by the target)
          node_dns.define_singleton_method(:resolve_txt) do |_domain, _timeouts|
            msg = Resolv::DNS::Message.new
            msg.rcode = Resolv::DNS::RCode::NoError
            msg.add_answer(Resolv::DNS::Name.create('alias.test.'), 300, Resolv::DNS::Resource::IN::CNAME.new(Resolv::DNS::Name.create('target.test.')))
            msg.add_answer(Resolv::DNS::Name.create('target.test.'), 60, Resolv::DNS::Resource::IN::TXT.new('name Plain Baseline'))
            msg
          end

          records = node_dns.resolve('alias.test', 'TXT')

          assert_equal [{ value: 'name Plain Baseline', ttl: 60, dnssec: nil }], records
        end

        # port-only (hazards pass): the TCP fallback sends its query under a fresh random id from the stdlib allocator (as
        # Resolv's own senders and c-ares do), never under the Message's process-wide counter, frees it with the socket,
        # and accepts only a reply carrying that id
        it 'sends the TCP fallback query under a fresh random id, frees it with the socket and refuses a reply under another id' do
          server = TCPServer.new('127.0.0.1', 0)
          port = server.addr[1]
          wire_ids = []
          thread = Thread.new do
            2.times do |n|
              sock = server.accept
              begin
                len = sock.read(2).unpack1('n')
                query = Resolv::DNS::Message.decode(sock.read(len))
                wire_ids << query.id
                reply = Resolv::DNS::Message.new(n == 0 ? query.id : query.id ^ 1) # the second reply carries another id
                reply.qr = 1
                reply.rcode = Resolv::DNS::RCode::NoError
                query.each_question { |qname, qtype| reply.add_question(qname, qtype) }
                reply.add_answer(Resolv::DNS::Name.create('config.test.'), 60, Resolv::DNS::Resource::IN::TXT.new('name Over TCP'))
                data = reply.encode
                sock.write([data.bytesize].pack('n') + data)
              ensure
                sock.close
              end
            end
          end
          thread.report_on_exception = false

          node_dns = Triauth::Resolvers::SystemDns.new
          name = Resolv::DNS::Name.create('config.test.')
          msgs = Array.new(2) do
            msg = Resolv::DNS::Message.new
            msg.rd = 1
            msg.add_question(name, Resolv::DNS::Resource::IN::TXT)
            msg
          end

          # the stdlib allocator is wrapped to record what the exchange allocates and frees
          allocated = []
          freed = []
          real_allocate = Resolv::DNS.method(:allocate_request_id)
          real_free = Resolv::DNS.method(:free_request_id)
          Resolv::DNS.define_singleton_method(:allocate_request_id) { |h, p| real_allocate.call(h, p).tap { |id| allocated << [h, p, id] } }
          Resolv::DNS.define_singleton_method(:free_request_id) do |h, p, id|
            freed << [h, p, id]
            real_free.call(h, p, id)
          end
          begin
            reply = node_dns.send(:tcp_exchange, msgs[0], name, '127.0.0.1', port, 2)
            err = assert_raises(Resolv::ResolvError) { node_dns.send(:tcp_exchange, msgs[1], name, '127.0.0.1', port, 2) }
          ensure
            Resolv::DNS.define_singleton_method(:allocate_request_id, real_allocate)
            Resolv::DNS.define_singleton_method(:free_request_id, real_free)
            thread.join(5)
            server.close
          end

          assert_equal(['name Over TCP'], reply.answer.map { |_n, _ttl, data| data.strings.join })
          assert_equal wire_ids[0], reply.id
          assert_equal [['127.0.0.1', port, wire_ids[0]], ['127.0.0.1', port, wire_ids[1]]], allocated # the allocated ids are the ones on the wire
          assert_equal allocated, freed # and both are freed with their sockets
          assert_match(/unexpected id/, err.message)
          assert_nil Resolv::DNS::RequestID[['127.0.0.1', port]]
        end
      end
    end
  end
end

TestInternals.resolvers if __FILE__ == $PROGRAM_NAME
