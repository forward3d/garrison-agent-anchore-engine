module Garrison
  class AnchoreEngine
    include HTTParty

    def initialize(url, user, pass)
      self.class.base_uri url
      @options = {
        basic_auth: {
          username: user,
          password: pass
        },
        logger: Logging,
        log_level: :debug
      }
    end

    def latest_images(analysis_status: nil)
      @latest_images = {}

      images = self.class.get("/v1/images", @options)
      images.select! { |i| i["analysis_status"] == analysis_status } if analysis_status

      images.each do |image|
        image['image_detail'].each do |detail|
          fulltag = detail['fulltag']
          tagts = DateTime.parse(detail['created_at'])

          unless @latest_images.include?(fulltag)
            @latest_images[fulltag] = detail
          else
            lasttagts = DateTime.parse(@latest_images[fulltag]['created_at'])
            if tagts >= lasttagts
              @latest_images[fulltag] = detail
            end
          end
        end
      end

      @latest_images
    end

    def vuln_types(digest)
      path = File.join("/v1/images", digest, "vuln")
      self.class.get(path, @options)
    end

    def vulns(digest, type = "all")
      path = File.join("/v1/images", digest, "vuln", type)
      self.class.get(path, @options)
    end
  end
end
