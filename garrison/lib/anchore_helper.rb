module Garrison
  class AnchoreHelper

    def self.severity_to_severity(severity)
      case severity.downcase
      when "high"
        "high"
      when "medium"
        "medium"
      when "low"
        "low"
      when "negligible"
        "info"
      when "unknown"
        "medium"
      else
        "medium"
      end
    end

  end
end
