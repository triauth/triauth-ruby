# frozen_string_literal: true

desc 'Run the unit tests and the JSON conformance suites in one process'
task :test do
  sh 'ruby', '-Ilib', '-Itest', 'test/test.rb'
end

namespace :test do
  desc 'Run the unit tests only'
  task :unit do
    sh 'ruby', '-Ilib', '-Itest', 'test/test_unit.rb'
  end

  desc 'Run the JSON conformance suites only'
  task :json do
    sh 'ruby', '-Ilib', '-Itest', 'test/test_json.rb'
  end
end

desc 'Run the full suite under SimpleCov with the 95 percent gate on lines and branches'
task :coverage do
  sh({ 'COVERAGE' => '1' }, 'ruby', '-Ilib', '-Itest', 'test/test.rb')
end

desc 'Lint lib and test with RuboCop'
task :lint do
  sh 'rubocop', 'lib', 'test'
end

desc 'Build the YARD documentation; any warning fails the build'
task :doc do
  sh 'yard', 'doc', '--fail-on-warning'
end

desc 'Build the gem'
task :build do
  sh 'gem', 'build', 'triauth.gemspec'
end

desc 'Run the AI security reviews with the agent CLIs (AGENT=, SCOPE=, EFFORT=, JOBS=, REFERENCE= narrow a run)'
task :ai_review do
  flags = %w[agent scope effort jobs].filter_map { |k| (v = ENV.fetch(k.upcase, nil)) && "--#{k}=#{v}" }
  sh 'ruby', 'test/ai-reviews/_harness/run.rb', *flags
end

task default: :test
