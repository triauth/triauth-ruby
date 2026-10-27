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


module Triauth
  # The base error type used throughout triauth-ruby, carrying the `code`, `reason`, and `message` of the
  # error object that Triauth API methods return, and `data` for the log entry.
  class Error < StandardError
    # The issue tracker to which internal errors should be reported
    ISSUES_URL = 'https://github.com/triauth/triauth-ruby/issues'
    private_constant :ISSUES_URL

    # @return [String] The error code (e.g., `request_denied`).
    attr_reader :code
    # @return [String, nil] The reason (only on errors about one field, e.g., `too_long`).
    attr_reader :reason
    # @return [Hash] Optional metadata, with `cause` stripped.
    attr_reader :data
    # @return [Time] The time the error was created.
    attr_reader :ts

    # @param error [Hash] The error object returned by Triauth API methods, `{code: String, reason: String (optional), message: String}`: the error
    #   code (e.g., `request_denied`), the reason (only on errors about one field, e.g., `too_long`),
    #   and a human-readable message.
    # @param data [Hash] Optional metadata; `cause` (if present) is stripped from `data` (defaults to `{}`).
    def initialize(error, data = {})
      super(error[:message])

      # `this.name = this.constructor.name` has no counterpart: a Ruby exception reports its class name itself

      @code = error[:code]
      @reason = error[:reason]

      @data = data.dup
      @data.delete(:cause) # the JS `cause` is Ruby's own `Exception#cause`, set automatically when raised inside a `rescue`

      @ts = Time.now
    end

    # Normalizes any thrown value into the `{error: {code, reason?, message}}` shape returned by Triauth API methods,
    # and logs it via `config[:logger]`. Validation errors (the errors about one field, which carry a `reason`) are
    # logged at `info`; other `Triauth::Error`s at `warn`. Anything else is an internal error (`internal_error`) logged
    # at `error` with the original error as `cause`.
    #
    # @param err [Object] The thrown value (typically a `Triauth::Error`, but anything is accepted).
    # @param config [Hash] Effective per-call config; only `config[:logger]` is consulted here.
    #
    # @return [Hash] `{error: {code: String, reason: String (optional), message: String}}`
    def self.process(err, config)
      if err.is_a?(Error)

        # Validation errors are logged with info severity
        if !err.reason.nil?
          Helpers.log(config, :info, "Validation error - #{err.message} (#{err.code})", { cause: err })
        else
          Helpers.log(config, :warn, "#{err.message} (#{err.code})", { cause: err })
        end

        return {
          error: err.reason.nil? ? { code: err.code, message: err.message } : { code: err.code, reason: err.reason, message: err.message }
        }

      else
        Helpers.log(
          config, :error,
          "Internal error: this is a defect in triauth-ruby - please report it at #{ISSUES_URL} together with the stack trace",
          { cause: err }
        )

        return {
          error: {
            code: 'internal_error',
            message: 'Internal error'
          }
        }

      end
    end
  end
end
