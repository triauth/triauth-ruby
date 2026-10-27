# frozen_string_literal: true

class DnsResolverStub < Triauth::Resolvers::Base
  def initialize(domain_records = {}, options = {}, config = {})
    super()
    @domain_records = domain_records
    @options = options
    @config = Triauth::Helpers.object_assign({}, Triauth.config, config)
  end

  # Four parameters, as `Base#resolve_config` passes four (JS ignores the extra argument); the records map and the
  # record types are keyed by Symbols (`{ 'config.test': { TXT: [...] } }`, the fixture parsed with `symbolize_names`).
  def resolve(domain_name, type, _options = {}, _config = {})
    records = @domain_records[domain_name.to_sym]

    # `return new Promise((resolve, reject) => {...})`: the promise body runs inline; `resolve(x)` is `return x`, `reject(err)` is `raise err`
    if records.is_a?(Hash) && records[:_error]
      raise records[:_error]
    end

    retval = (records.nil? ? {} : records)[type.to_s.to_sym] || []
    retval = retval.map { |record| Triauth::Helpers.is_string(record) ? { value: record, ttl: 1800, dnssec: true } : record }
    return retval
  end
end
