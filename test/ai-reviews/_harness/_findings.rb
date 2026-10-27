# frozen_string_literal: true

# Pure helpers for parsing findings and rolling up status.
# Kept separate from run.rb so they can be unit-tested without launching agents.
module Findings
  # groups: 1=prefix (incl. id+severity brackets), 2=id, 3=severity, 4=[reviewed] marker, 5=rest
  HEADING = /^(###\s+\[([A-Z]+-\d+)\]\s+\[([a-z]+)\])(\s+\[reviewed\])?(\s.*)?$/
  SEV_RANK = { 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 }.freeze

  module_function

  def finding_ids(text)
    ids = Set.new
    text.split(/\r?\n/).each do |line|
      m = HEADING.match(line)
      ids << m[2] if m
    end
    ids
  end

  # The number of a finding ID: `AUTH-003` -> 3.
  def finding_number(id)
    id[(id.rindex('-') + 1)..].to_i
  end

  # The highest finding number in the text, 0 when it has no finding. Numbers are append-only: a review's
  # `next_id` never drops below this plus one, so a removed finding's number is never used again.
  def highest_finding_number(text)
    highest = 0
    finding_ids(text).each { |id| highest = [highest, finding_number(id)].max }
    highest
  end

  # The [reviewed] findings of the text, keyed by ID, each as the lines a run must carry over verbatim: its
  # heading and the quoted human review note(s) under it.
  def reviewed_entries(text)
    entries = {}
    current = nil
    text.split(/\r?\n/).each do |line|
      m = HEADING.match(line)
      if m
        current = m[4] ? [line] : nil
        entries[m[2]] = current if current
        next
      end
      if /\A\#{1,2} /.match?(line)
        current = nil
        next
      end
      current << line if current && line.start_with?('> ')
    end
    entries
  end

  # What a run must not do to the findings it was given: bring back a number below the committed `next_id`
  # (`committed_next_id`, with `before_ids` the committed IDs), or drop or alter a [reviewed] finding it started
  # from (`before_reviewed`, as `reviewed_entries` lists them). Returns the fault as text, or nil.
  def findings_fault(run, text)
    recycled = finding_ids(text).to_a.select { |id| !run[:before_ids].include?(id) && finding_number(id) < run[:committed_next_id] }
    return "reused the retired number(s) #{recycled.join(', ')} (next_id is #{run[:committed_next_id]})" if recycled.length > 0

    kept = reviewed_entries(text)
    run[:before_reviewed].each do |id, lines|
      return "dropped or altered the [reviewed] finding #{id}" if kept[id]&.join("\n") != lines.join("\n")
    end
    nil
  end

  # Roll up status from the worst OPEN (non-[reviewed]) finding: high/critical→fatal, medium→warnings,
  # low/info/none→good-to-go. [reviewed] findings are accepted and excluded.
  def compute_status(text)
    worst = -1
    text.split(/\r?\n/).each do |line|
      m = HEADING.match(line)
      next if !m || m[4]                              # skip non-headings and [reviewed] findings

      worst = [worst, SEV_RANK[m[3]]].max if SEV_RANK.key?(m[3])
    end
    return 'fatal' if worst >= SEV_RANK['high']
    return 'warnings' if worst == SEV_RANK['medium']

    'good-to-go'
  end
end
