# frozen_string_literal: true

# Runtime-lane helpers shared by the test files.
# The Node lane always runs here: a server-side port has no browser lane, so `it_node` and
# `describe_node` are plain forwards and `IS_NODE` is always true.
IS_NODE = true

module Minitest
  class Spec
    module DSL
      def it_node(desc, &)
        it(desc, &)
      end

      def describe_node(desc, &)
        describe(desc, &)
      end

      # Port-only lane: `TRIAUTH_OFFLINE=1` skips the tests that reach the public network.
      def it_online(desc, &)
        offline = ENV.fetch('TRIAUTH_OFFLINE', nil)
        if offline.nil? || offline.empty?
          it(desc, &)
        else
          it(desc) { skip 'offline (TRIAUTH_OFFLINE)' }
        end
      end
    end
  end
end
