# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "triauth"
  spec.version = "0.0.1"
  spec.summary = "triauth: password-less sign-in for web (placeholder)"
  spec.description = "triauth: password-less sign-in for web. " \
                     "Placeholder - real release coming; see https://www.triauth.org/"
  spec.authors = ["Triauth"]
  spec.email = ["devs@triauth.org"]
  spec.homepage = "https://www.triauth.org/"
  spec.license = "BSD-3-Clause"
  spec.required_ruby_version = ">= 3.0"
  spec.files = ["lib/triauth.rb", "README.md", "LICENSE"]
  spec.metadata = {
    "homepage_uri" => "https://www.triauth.org/",
    "source_code_uri" => "https://github.com/triauth/triauth-ruby",
    "rubygems_mfa_required" => "true"
  }
end
