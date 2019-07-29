module Garrison
  module Checks
    class CheckImages < Check

      def settings
        self.source ||= 'anchore-engine'
        self.family ||= 'software'
        self.type   ||= 'security'
      end

      def perform
        images = latest_images
        Logging.debug "Retrieved #{images.count} images from Anchore Engine API"

        images.each do |_tag, image|
          vulns = fetch_vulns(image["imageDigest"])
          next if vulns.nil? || vulns["vulnerabilities"].empty?
          vulns["vulnerabilities"].each do |vulnerability|
            raise_alert(image, vulnerability)
          end
        end
      end

      private

      def get(path)
        auth = { username: options[:username], password: options[:password] }
        HTTParty.get(File.join(options[:url], path), basic_auth: auth, logger: Logging, log_level: :debug)
      end

      def latest_images
        latest = {}

        fetch_images.each do |image|
          image['image_detail'].each do |detail|
            fulltag = detail['fulltag']
            tagts = DateTime.parse(detail['created_at'])

            unless latest.include?(fulltag)
              latest[fulltag] = detail
            else
              lasttagts = DateTime.parse(latest[fulltag]['created_at'])
              if tagts >= lasttagts
                latest[fulltag] = detail
              end
            end
          end
        end

        latest
      end

      def fetch_images
        Logging.info "Fetching images from Anchore Engine API"
        get("images").select { |i| i["analysis_status"] == "analyzed" }
      end

      def fetch_vulns(image_digest)
        vuln_types_path = File.join("images", image_digest, "vuln")
        vuln_path       = File.join("images", image_digest, "vuln", options[:vuln_type])

        Logging.debug "Fetching available vuln types for #{image_digest}"
        if get(vuln_types_path).include?(options[:vuln_type])

          Logging.info "Fetching vulns for #{image_digest}"
          get(vuln_path)
        end
      end

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
