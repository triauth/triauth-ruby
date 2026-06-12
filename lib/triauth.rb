# frozen_string_literal: true

# Official placeholder for the triauth project. See https://www.triauth.org/.
module Triauth
  VERSION = "0.0.1"

  MESSAGE = "triauth for Ruby has not been released yet.\n" \
            "This package name is reserved by the triauth project to prevent supply-chain confusion.\n" \
            "See https://www.triauth.org/"

  def self.method_missing(*) = raise(NotImplementedError, MESSAGE)

  def self.respond_to_missing?(*) = true
end
