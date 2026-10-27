# frozen_string_literal: true

require_relative 'setup'
# The demo zone, served from the fixture - installed before any suite loads.
require_relative 'stubs/zone_resolver'
require_relative 'test_authentication'
require_relative 'test_identity'
require_relative 'test_signing'
require_relative 'test_attestation'
require_relative 'test_validation'
require_relative 'test_internals'
