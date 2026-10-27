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
  # An implementation of simple logger that is set as the default value for `Triauth.config[:logger]` with output to the console.
  class Logger
    # The port of the JS `console`, the default `output` of the logger that `Triauth.config[:logger]` is set to: `debug` and
    # `info` write one line to `$stdout`, `warn` and `error` one line to `$stderr`. A line is the parts joined by a space,
    # Strings as they are, other values via `inspect`.
    module CONSOLE
      # @param args [Array<Object>] The parts of one log line.
      def self.debug(*args)
        write($stdout, args)
      end

      # @param args [Array<Object>] The parts of one log line.
      def self.info(*args)
        write($stdout, args)
      end

      # @param args [Array<Object>] The parts of one log line.
      def self.warn(*args)
        write($stderr, args)
      end

      # @param args [Array<Object>] The parts of one log line.
      def self.error(*args)
        write($stderr, args)
      end

      # Writes the parts as one line to `io`: Strings as they are, other values via `inspect`.
      def self.write(io, args)
        io.puts(args.map { |part| part.is_a?(String) ? part : part.inspect }.join(' '))
      end
      private_class_method :write
    end

    # @return [Object, nil] The object to which log messages are sent (see {#initialize}).
    attr_accessor :output
    # @return [String] A minimal level of messages that get logged to output. One of `debug`, `info`, `warn`, `error`.
    attr_accessor :log_level
    # @return [String] A prefix to use when logging messages.
    attr_accessor :prefix
    # @return [String, false, nil] The correlation/context identifier shown in the `[cid:...]` tag.
    attr_accessor :cid

    # @param output [Object, nil] An object to which log messages will be sent, that should implement `debug`, `info`, `warn`, `error` methods, just like {CONSOLE} (the port of the native `console`). Defaults to nil.
    # @param options [Hash] Additional configurations options. Defaults to `{}`.
    # @option options [String] :logLevel ('warn') A minimal level of messages that get logged to output. One of `debug`, `info`, `warn`, `error`. Defaults to 'warn'.
    # @option options [String] :prefix ('[triauth]') A prefix to use when logging messages. Defaults to '[triauth]'.
    # @option options [String, false, nil] :cid (nil) A correlation/context identifier shown in the `[cid:...]` tag, to identify log lines belonging to a single API call. A nil value leaves the tag empty here; `false` explicitly suppresses it. (The `spawn` factory resolves nil into an auto-generated id.)
    def initialize(output = nil, options = {})
      @output = output
      @log_level = options[:logLevel].nil? || options[:logLevel].empty? ? 'warn' : options[:logLevel]
      @prefix = options[:prefix].nil? || options[:prefix].empty? ? '[triauth]' : options[:prefix]
      @cid = options[:cid]
    end

    # Returns a child logger for a single API call, resolving the correlation id (`cid`):
    #   - nil: "autofill" - inherit this logger's `cid` or mint a fresh one.
    #   - `false`: explicit opt-out - stored as-is and suppressed by `format_message` (no `[cid:...]` tag).
    #   - string: used verbatim as the correlation id.
    #
    # @param cid [String, false, nil] explicit id, `false` to opt out, or nil to autofill. Defaults to nil.
    # @return [Logger]
    def spawn(cid = nil)
      return Logger.new(
        @output,
        {
          logLevel: @log_level,
          prefix: @prefix,
          cid: if cid.nil?
                 # `this.cid || this.#generateCid()`: the JS falsy set of the `string|false|null` cid (nil, false and '') mints a fresh id
                 @cid.nil? || @cid == false || @cid == '' ? generate_cid : @cid
               else
                 cid
               end
        }
      )
    end

    # Logs a message at the `debug` level, when the logger's `logLevel` admits it.
    #
    # @param args [Array<Object>] Values to log. Passed through verbatim to the output's `debug` function,
    #                             behind the logger's prefix, correlation id (when set), and level tag.
    def debug(*args)
      if %w[debug].include?(@log_level)
        @output&.debug(*format_message('debug', args))
      end
    end

    # Logs a message at the `info` level, when the logger's `logLevel` admits it.
    #
    # @param args [Array<Object>] Values to log. Passed through verbatim to the output's `info` function,
    #                             behind the logger's prefix, correlation id (when set), and level tag.
    def info(*args)
      if %w[debug info].include?(@log_level)
        @output&.info(*format_message('info', args))
      end
    end

    # Logs a message at the `warn` level, when the logger's `logLevel` admits it.
    #
    # @param args [Array<Object>] Values to log. Passed through verbatim to the output's `warn` function,
    #                             behind the logger's prefix, correlation id (when set), and level tag.
    def warn(*args)
      if %w[debug info warn].include?(@log_level)
        @output&.warn(*format_message('warn', args))
      end
    end

    # Logs a message at the `error` level, when the logger's `logLevel` admits it.
    #
    # @param args [Array<Object>] Values to log. Passed through verbatim to the output's `error` function,
    #                             behind the logger's prefix, correlation id (when set), and level tag.
    def error(*args)
      if %w[debug info warn error].include?(@log_level)
        @output&.error(*format_message('error', args))
      end
    end

    private

    def format_message(log_level, args)
      parts = [@prefix]

      if @cid && @cid != ''
        parts.push("[cid:#{@cid}]")
      end

      parts.push("[#{log_level}]")

      return [*parts, *args]
    end

    def generate_cid
      return rand(36**8).to_s(36).rjust(8, '0')
    end
  end
end
