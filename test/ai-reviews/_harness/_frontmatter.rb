# frozen_string_literal: true

# Minimal YAML-frontmatter parse/serialize for the ai-reviews format.
#
# Deliberately tiny and dependency-free (the library has zero runtime deps and we keep the tooling
# the same). It handles exactly what our review files use: a leading `---` block of top-level
# `key: value` pairs, plus one nested map (`settings:`) with 2-space-indented children. Anything
# fancier than that is out of scope on purpose. (A YAML library would quote and order differently,
# and the stamps must stay byte-compatible with the ones triauth-js writes.)
module Frontmatter
  module_function

  def strip_quotes(v)
    if v.length >= 2 && ((v[0] == '"' && v[-1] == '"') || (v[0] == "'" && v[-1] == "'"))
      return v[1..-2]
    end

    v
  end

  def format_scalar(v)
    s = v.to_s
    # Quote when a bare scalar could confuse a YAML reader (leading indicator char, or a `: ` / `#`).
    if s == '' || s.match?(/\A[\s\-?:>@&*!|%#'"\[\]{}]/) || s.match?(/:\s|\s#|\s\z/)
      return "\"#{s.gsub('"', '\\"')}\""
    end

    s
  end

  # parse(text) -> { data:, body: }. `data` is a plain Hash with String keys; nested maps become Hashes.
  def parse(text)
    m = /\A---\r?\n([\s\S]*?)\r?\n---\r?\n?/.match(text)
    return { data: {}, body: text } unless m

    body = m.post_match
    data = {}
    block = nil # current nested-map key, or nil at top level
    m[1].split(/\r?\n/).each do |raw|
      next if raw.strip.empty? || raw.lstrip.start_with?('#')

      indented = raw.match?(/\A\s+\S/)
      line = raw.strip
      idx = line.index(':')
      next if idx.nil?

      key = line[0...idx].strip
      val = strip_quotes(line[(idx + 1)..].strip)
      if indented && block
        data[block][key] = val
      elsif val == ''
        data[key] = {}
        block = key
      else
        data[key] = val
        block = nil
      end
    end
    { data: data, body: body }
  end

  # serialize(data, body) -> text. Emits keys in insertion order; nested Hashes become indented maps.
  def serialize(data, body)
    lines = ['---']
    data.each do |k, v|
      if v.is_a?(Hash)
        lines << "#{k}:"
        v.each { |sk, sv| lines << "  #{sk}: #{format_scalar(sv)}" }
      else
        lines << "#{k}: #{format_scalar(v)}"
      end
    end
    lines << '---'
    "#{lines.join("\n")}\n\n#{body.sub(/\A\r?\n+/, '')}"
  end
end
