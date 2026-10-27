# frozen_string_literal: true

if ENV['COVERAGE']
  require 'simplecov'
  SimpleCov.start do
    enable_coverage :branch
    skip '/test/'
    minimum_coverage line: 95, branch: 95
  end
end

require 'triauth'
require 'minitest/autorun'
require_relative 'env'

class StubLogger
  def debug(*); end
  def info(*); end
  def warn(*); end
  def error(*); end

  # `spawn` returns a fresh child logger so that the
  # `config.logger?.spawn?.(config.cid) || config.logger` line in every API
  # entrypoint hits the truthy branch under tests.
  def spawn(_cid = nil)
    StubLogger.new
  end
end
Triauth.config[:logger] = StubLogger.new
