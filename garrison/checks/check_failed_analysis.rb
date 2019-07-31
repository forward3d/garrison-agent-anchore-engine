module Garrison
  module Checks
    class CheckFailedAnalysis < Check

      def settings
        self.severity ||= 'critical'
        self.source   ||= 'anchore-engine'
        self.family   ||= 'software'
        self.type     ||= 'security'
      end

      def perform
        anchore = AnchoreEngine.new(options[:url], options[:username], options[:password])

        images = anchore.latest_images(analysis_status: "analysis_failed")
        Logging.debug "Retrieved #{images.count} images from Anchore Engine API"

        images.each do |_tag, image|
          raise_alert(image)
        end
      end

      private

      def raise_alert(image)
        alert(
          name: "Anchore Analysis Failed",
          external_severity: "critical",
          target: image["fulltag"],
          detail: "analysis_failed",
          finding: image.to_json,
          no_repeat: true,
          finding_id: image["fulldigest"]
        )
      end
    end
  end
end
