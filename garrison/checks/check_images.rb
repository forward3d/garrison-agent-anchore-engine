module Garrison
  module Checks
    class CheckImages < Check

      def settings
        self.source ||= 'anchore-engine'
        self.family ||= 'software'
        self.type   ||= 'security'
      end

      def perform
        anchore = AnchoreEngine.new(options[:url], options[:username], options[:password])

        images = anchore.latest_images(analysis_status: "analyzed")
        Logging.debug "Retrieved #{images.count} images from Anchore Engine API"

        images.each do |_tag, image|
          Logging.debug "Fetching available vuln types for #{image["imageDigest"]}"
          vuln_types = anchore.vuln_types(image["imageDigest"])

          if vuln_types.include?(options[:vuln_type])
            Logging.info "Fetching vulns for #{image["imageDigest"]}"
            vulns = anchore.vulns(image["imageDigest"], options[:vuln_type])

            next if vulns.nil? || vulns["vulnerabilities"].empty?
            vulns["vulnerabilities"].each do |vulnerability|
              raise_alert(image, vulnerability)
            end
          end
        end
      end

      private

      def raise_alert(image, vulnerability)
        alert(
          name: 'Docker Image Vulnerability',
          external_severity: AnchoreHelper.severity_to_severity(vulnerability["severity"]),
          target: image["fulltag"],
          detail: "#{vulnerability["vuln"]} - #{vulnerability["package_name"]}",
          finding: { image: image, vulnerability: vulnerability }.to_json,
          no_repeat: true,
          finding_id: File.join(image["fulltag"], vulnerability["vuln"], image["imageDigest"][0..18]),
          urls: [
            {
              name: "Vulnerability",
              url: vulnerability["url"]
            }
          ],
          key_values: [
            {
              key: "vuln_type",
              value: options[:vuln_type]
            },
            {
              key: "vulnerability",
              value: vulnerability["vuln"]
            }
          ]
        )
      end
    end
  end
end
