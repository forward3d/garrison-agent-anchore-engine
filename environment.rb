require 'bundler'
Bundler.require(:default)
ROOT = File.dirname(__FILE__)

Dir[File.join(ROOT, 'garrison/lib/*.rb')].each do |file|
  require file
end

Dir[File.join(ROOT, 'garrison/checks/*.rb')].each do |file|
  require file
end

Garrison::Api.configure do |config|
  config.url  = ENV['GARRISON_URL']
  config.uuid = ENV['GARRISON_AGENT_UUID']
end

Garrison::Logging.info('Garrison Agent - Anchore Engine')

module Garrison
  module Checks
    @options = {}
    @options[:url]       = ENV['GARRISON_ANCHORE_URL']
    @options[:username]  = ENV['GARRISON_ANCHORE_USER']
    @options[:password]  = ENV['GARRISON_ANCHORE_PASS']
    @options[:vuln_type] = ENV['GARRISON_ANCHORE_VULN_TYPE'] ||= 'all'
  end
end
