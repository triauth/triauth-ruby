#!/usr/bin/env ruby
# frozen_string_literal: true

# AI-review runner (`rake ai_review`).
#
# Every (agent × scope) pair is one headless CLI run. All runs start at once (cap them with
# --jobs), and each one independently:
#   1. launches the agent CLI so it writes/updates test/ai-reviews/<agent>/<scope>.md following
#      GUIDE.md, with the CLI's output captured to a per-run log file, then
#   2. checks that the run was served by the model the adapter names (where the CLI reports it),
#      that it reused no finding number below the committed `next_id`, and that it kept every
#      [reviewed] finding with its human note, then stamps the controlled frontmatter
#      (model/version/commit/date/next_id/settings) authoritatively and reports the finding IDs
#      new or removed since the last commit.
#
# It never commits; read the reviews, inspect `git diff test/ai-reviews/` and commit yourself.
#
# Usage (the Rake task turns each variable into the matching --flag of this script):
#   rake ai_review                                     # all agents × all scopes, all at once
#   rake ai_review AGENT=claude SCOPE=verify           # narrow it down
#   rake ai_review EFFORT=medium                       # override the reasoning effort
#   rake ai_review JOBS=4                              # at most 4 agent CLIs running at a time
#
# NOTE: requires the relevant CLI(s) installed and authenticated (`claude`, `codex`). The exact
# flags below were written against claude-code 2.1.x and codex-cli 0.158; adjust the adapters if
# your CLI versions differ. Confirm the codex `model`/`model_id` matches what your account actually runs.

require 'json'
require 'fileutils'
require 'open3'
require 'tmpdir'
require_relative '_frontmatter'
require_relative '_findings'

$stdout.sync = true
$stderr.sync = true
Encoding.default_external = Encoding::UTF_8   # the review files and the CLIs' output are UTF-8 whatever the locale

HARNESS_DIR = __dir__
REPO_ROOT = File.expand_path('../../..', HARNESS_DIR)
# The gem version is Triauth::VERSION in lib/triauth/version.rb.
LIB_VERSION = File.read(File.join(REPO_ROOT, 'lib', 'triauth', 'version.rb'))[/^\s*VERSION = '([^']+)'/, 1]

SCOPES = %w[protocol authenticate check ping whois attest sign stamp verify validate].freeze

# Per-agent adapters. `id` names the review directory (test/ai-reviews/<id>/) and the `--agent`
# filter. `params` is an open map (effort + anything else) and `cmd` maps it to that CLI's flags.
# Both the params and the resolved model are recorded in each review's `settings`/`model_id`.
# `env` is added to the CLI's environment. `verify({ stdout:, stderr: }, model_id)` inspects the
# CLI's output after a clean exit and returns a problem string, or nil when the run was served by
# `model_id`; an adapter without it is judged on exit status and the written file alone.
AGENTS = [
  {
    id: 'claude',
    model: 'Fable 5.1',
    model_id: 'claude-fable-5-1',
    params: { effort: 'max' },
    # Claude Code re-runs a safety-refused request on a fallback model by default (Fable's
    # dual-use classifier routes cyber/bio refusals to Opus) and may swap an unavailable model.
    # CLAUDE_CODE_NO_MODEL_FALLBACK forbids every substitution, so such a run ends instead.
    env: { 'CLAUDE_CODE_NO_MODEL_FALLBACK' => '1' },
    cmd: lambda do |prompt, p|
      ['claude', [
        '-p', prompt,
        '--model', 'claude-fable-5-1',
        '--effort', p[:effort],
        '--permission-mode', 'acceptEdits',
        '--allowedTools', 'Read', 'Edit', 'Write', 'Grep', 'Glob',
        '--output-format', 'json'
      ]]
    end,
    # The JSON result carries how the session stopped and `modelUsage`, keyed by the model that
    # actually answered each request (a server-side fallback shows up under the fallback's id).
    verify: lambda do |out, model_id|
      r = begin
        JSON.parse(out[:stdout])
      rescue JSON::ParserError
        nil
      end
      return 'printed no JSON result' unless r.is_a?(Hash)

      if r['is_error'] || r['subtype'] != 'success'
        errors = r['errors'].is_a?(Array) && !r['errors'].empty? ? ": #{r['errors'].join('; ')}" : ''
        return "ended with #{r['subtype']}#{errors}"
      end
      return 'refused the task (stop_reason: refusal)' if r['stop_reason'] == 'refusal'

      served = (r['modelUsage'] || {}).map { |id, u| u['canonicalModel'] || id }
      return 'reported no model usage' if served.empty?

      others = served.reject { |id| id == model_id }
      others.empty? ? nil : "served by #{others.uniq.join(', ')}"
    end
  },
  {
    id: 'codex',
    model: 'GPT-6 Astra',
    model_id: 'gpt-6-astra',
    params: { effort: 'xhigh' },
    # The workspace-write sandbox confines writes to the repo.
    cmd: lambda do |prompt, p|
      ['codex', [
        'exec', prompt,
        '-m', 'gpt-6-astra',
        '-s', 'workspace-write',
        '-c', "model_reasoning_effort=#{p[:effort]}",
        '--skip-git-repo-check',
        '--color', 'never'
      ]]
    end,
    # codex exec prints its transcript on stderr: a `model: <id>` header line and, when OpenAI
    # reroutes a turn to another model, `model rerouted: <from> -> <to> (<reason>)`. The --json
    # stream carries neither, so the adapter stays on text output and reads the transcript.
    verify: lambda do |out, model_id|
      all = "#{out[:stderr]}\n#{out[:stdout]}"
      rerouted = /^model rerouted: (\S+) -> (\S+) \((.*)\)$/.match(all)
      return "served by #{rerouted[2]} (model rerouted: #{rerouted[1]} -> #{rerouted[2]}, #{rerouted[3]})" if rerouted

      header = /^model: (\S+)$/.match(all)
      return 'printed no model header' unless header

      header[1] == model_id ? nil : "configured for #{header[1]}"
    end
  }
].freeze

# ---- helpers (defined before the top-level code that calls them) -------------
# `console.error` + `process.exit(2)` of run.mjs, in one call.
def die(message)
  warn message
  exit 2
end

# `spawnSync(bin, ['--version'])` of run.mjs: false when the CLI is missing or does not run.
def cli_present?(bin)
  _, status = Open3.capture2e(bin, '--version')
  status.success?
rescue SystemCallError
  false
end

# The short SHA of HEAD, plus `+dirty` when tracked files other than the reviews have uncommitted
# changes, so a review of uncommitted code never passes for a review of HEAD. Nil when `dir` is
# not a git checkout.
def describe_checkout(dir)
  head, status = Open3.capture2('git', '-C', dir, 'rev-parse', '--short', 'HEAD', err: File::NULL)
  return nil unless status.success?

  porcelain, = Open3.capture2('git', '-C', dir, 'status', '--porcelain', '--untracked-files=no', '--', '.', ':!test/ai-reviews', err: File::NULL)
  dirty = !porcelain.strip.empty?
  "#{head.strip}#{'+dirty' if dirty}"
end

def committed_version(rel_path)
  out, status = Open3.capture2('git', 'show', "HEAD:#{rel_path}", chdir: REPO_ROOT, err: File::NULL)
  status.success? ? out : ''
end

def build_prompt(scope, agent_id)
  out_path = "test/ai-reviews/#{agent_id}/#{scope}.md"
  [
    "Perform an AI security review of the triauth-ruby library for the scope \"#{scope}\".",
    'Follow test/ai-reviews/_harness/GUIDE.md EXACTLY — read it first, then the source files it lists for this scope, the README\'s Best Practices and Security Considerations section, and the matching README section.',
    "Read the existing review at #{out_path} if present and obey the ID rule: update an existing finding by its ID, allocate every new ID from next_id upwards, remove a finding that no longer applies, and never renumber or reuse a number.",
    "Write your review to #{out_path}.",
    'You own only: scope, status, summary, and the ## Findings section. Leave the other frontmatter fields as placeholders — they are stamped after you. NEVER remove or alter a [reviewed] finding, its tag, any "Human review" note, or an "Engineer note", and never add the tag or such a note yourself.'
  ].join("\n")
end

# The next finding number a review may allocate: its `next_id`, or one past its highest finding when the
# field is absent. The runner keeps it monotonic, so a removed finding's number is never used again.
def next_id_of(text)
  parsed = Frontmatter.parse(text)
  [parsed[:data]['next_id'].to_i.nonzero? || 1, Findings.highest_finding_number(parsed[:body]) + 1].max
end

def stamp_metadata(text, run)
  parsed = Frontmatter.parse(text)
  body = parsed[:body]
  stamped = {
    'model' => run[:agent][:model],
    'model_id' => run[:agent][:model_id],
    'scope' => run[:scope],
    'lib_version' => LIB_VERSION,
    'commit' => HEAD_COMMIT,
    'reviewed_at' => TODAY,
    'status' => Findings.compute_status(body),          # derived from findings, not the model's assertion
    'summary' => parsed[:data]['summary'] || '',
    'next_id' => [run[:committed_next_id], Findings.highest_finding_number(body) + 1].max,   # never below the committed counter
    'settings' => run[:params].transform_keys(&:to_s)
  }
  Frontmatter.serialize(stamped, body)
end

def elapsed_since(started)
  s = (Time.now - started).round
  s < 60 ? "#{s}s" : "#{s / 60}m#{format('%02d', s % 60)}s"
end

# Launch one agent CLI; returns its captured stdout plus a short problem note (nil when the CLI
# exited cleanly and its adapter's `verify` accepted the run). stdin is /dev/null, stderr goes to
# the run's log file as it happens, stdout is appended to it at exit.
def launch(run)
  bin, args = run[:agent][:cmd].call(build_prompt(run[:scope], run[:agent][:id]), run[:params])
  reader, writer = IO.pipe
  pid = File.open(run[:log_path], 'w') do |log|
    Process.spawn(run[:agent].fetch(:env, {}), bin, *args, chdir: REPO_ROOT, in: File::NULL, out: writer, err: log)
  end
  writer.close                                        # the child holds its own copy
  stdout = reader.read
  reader.close
  _, status = Process.wait2(pid)
  stderr = File.read(run[:log_path])
  File.write(run[:log_path], stdout, mode: 'a')
  problem = if status.success?
              run[:agent][:verify]&.call({ stdout: stdout, stderr: stderr }, run[:agent][:model_id])
            elsif status.signaled?
              "killed by SIG#{Signal.signame(status.termsig)}"
            else
              "exited #{status.exitstatus}"
            end
  { stdout: stdout, problem: problem }
rescue SystemCallError => e
  { stdout: '', problem: "failed to start (#{e.message})" }
end

# One review end to end: launch, wait, verify, check the findings, stamp, report a single line with the
# finding IDs new and removed since the last commit. A failed run puts the review file back exactly as
# it was before the run.
def review(run)
  run[:log_path] = File.join(LOG_DIR, "#{run[:agent][:id]}-#{run[:scope]}.log")
  started = Time.now
  problem = launch(run)[:problem]
  label = "#{run[:agent][:model]} → #{run[:scope]} (#{elapsed_since(started)})"
  written = File.exist?(run[:abs_path]) ? File.read(run[:abs_path]) : nil
  fault = problem.nil? && !written.nil? ? Findings.findings_fault(run, written) : problem
  why = if fault
          "#{run[:agent][:id]} #{fault}"
        elsif written.nil?
          "#{run[:rel_path]} was not written"
        end
  if why
    touched = !written.nil? && written != run[:before]
    if touched
      run[:before].nil? ? FileUtils.rm_f(run[:abs_path]) : File.write(run[:abs_path], run[:before])
    end
    warn "✗ #{label}: #{why}#{", #{run[:rel_path]} restored" if touched}. Log: #{run[:log_path]}"
    return
  end
  text = stamp_metadata(written, run)
  File.write(run[:abs_path], text)
  run[:written] = true
  ids = Findings.finding_ids(text)
  added = ids.to_a.reject { |id| run[:before_ids].include?(id) }.length
  removed = run[:before_ids].to_a.reject { |id| ids.include?(id) }.length
  puts "✓ #{label}: wrote #{run[:rel_path]}, status: #{Frontmatter.parse(text)[:data]['status']}, #{added} new, #{removed} removed"
end

# ---- args -----------------------------------------------------------------
die 'Cannot find Triauth::VERSION in lib/triauth/version.rb.' unless LIB_VERSION
opts = {}
ARGV.each do |a|
  m = /\A--([^=]+)(?:=(.*))?\z/.match(a)
  opts[m[1]] = m[2] || true if m
end
agents = AGENTS.select { |a| !opts['agent'] || a[:id] == opts['agent'] }
scopes = SCOPES.select { |s| !opts['scope'] || s == opts['scope'] }
jobs = opts.key?('jobs') ? Integer(opts['jobs'], exception: false) : Float::INFINITY   # Infinity = every run at once
die "Unknown --agent. Known: #{AGENTS.map { |a| a[:id] }.join(', ')}" if agents.empty?
die "Unknown --scope. Known: #{SCOPES.join(', ')}" if scopes.empty?
die '--jobs takes a positive integer.' unless jobs == Float::INFINITY || (jobs.is_a?(Integer) && jobs >= 1)

HEAD_COMMIT = describe_checkout(REPO_ROOT)
die "#{REPO_ROOT} is not a git checkout." unless HEAD_COMMIT
warn "⚠ triauth-ruby has uncommitted changes; reviews are stamped #{HEAD_COMMIT}." if HEAD_COMMIT.end_with?('+dirty')
TODAY = Time.now.utc.strftime('%Y-%m-%d')

# ---- plan -----------------------------------------------------------------
# One entry per (agent × scope). Each agent CLI is probed once up front, so a missing CLI skips
# that agent as a whole, and the committed finding IDs are captured before anything runs.
runs = []
skipped = 0
agents.each do |agent|
  unless cli_present?(agent[:id])
    warn "⚠ '#{agent[:id]}' CLI not found on PATH — skipping #{agent[:model]}."
    skipped += 1
    next
  end
  params = agent[:params].merge(opts['effort'] ? { effort: opts['effort'] } : {})
  FileUtils.mkdir_p(File.join(REPO_ROOT, 'test', 'ai-reviews', agent[:id]))
  scopes.each do |scope|
    rel_path = "test/ai-reviews/#{agent[:id]}/#{scope}.md"
    abs_path = File.join(REPO_ROOT, rel_path)
    before = File.exist?(abs_path) ? File.read(abs_path) : nil
    committed = committed_version(rel_path)
    runs << {
      agent: agent, scope: scope, params: params, rel_path: rel_path, abs_path: abs_path,
      before: before,                                # restored when the run fails
      before_reviewed: Findings.reviewed_entries(before || ''),   # the [reviewed] findings the run must keep verbatim
      before_ids: Findings.finding_ids(committed),
      committed_next_id: next_id_of(committed)
    }
  end
end
if runs.empty?
  puts "Nothing to run: #{skipped} agent(s) skipped."
  exit 0
end

# ---- run ------------------------------------------------------------------
# The agent CLIs share the terminal only through their one-line results above. Each CLI's own
# output goes to <LOG_DIR>/<agent>-<scope>.log (stderr as it happens, stdout appended at exit),
# and stdin is closed so the concurrent processes never compete for the keyboard. A worker thread
# per job slot takes runs off the queue until it is empty.
LOG_DIR = Dir.mktmpdir('ai-review-')

puts "Running #{runs.size} review(s)#{jobs < runs.size ? ", #{jobs} at a time" : ' all at once'}. Logs: #{LOG_DIR}"
queue = Queue.new
runs.each { |run| queue << run }
queue.close
workers = Array.new([jobs, runs.size].min) do
  Thread.new do
    while (run = queue.pop)
      review(run)
    end
  end
end
workers.each(&:join)

written = runs.count { |run| run[:written] }
puts "\nDone: #{written} review(s) written, #{runs.size - written} failed, #{skipped} agent(s) skipped. Review 'git diff test/ai-reviews/' and commit."
