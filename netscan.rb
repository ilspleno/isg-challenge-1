#!/bin/env ruby

require 'optparse'
require 'pp'
require 'netaddr'
require 'terminal-table'

class Port
	# Basically just an Integer that can have flags set on it for ports. Port 80 responded to http or not

	attr_accessor :port, :http
	

	def initialize
		@port = nil
		@http = false
	end

	def initialize(port)
		@port = port
		@http = false
	end

	def initialize(port,http)
		@port = port
		@http = http
	end

	def to_s
		"#{@port}#{"*" if @http}"
	end

	def to_i
		@port
	end

end


class Netscan

	attr_reader :config

	@output = []

	def initialize(args)

		# Init options hash
		@config = {:outfile 	 => "netscan.log", 
		          :test_for_http => false}

		parser = OptionParser.new do |o|

			o.banner = "Usage: netscan.rb [options]"
			o.separator ""
			o.separator "Specific settings:"

			o.on "-n", "--network CIDR", "Network(s) to scan. Specify as a.b.c.d/n", "example: 10.14.0.0/16" do |n|
				# Validate that the network we got was actually an IP address with netmask
				if n =~ /\d+\.\d+\.\d+.\d+\/\d+/
					@config[:network] = n
				else
					puts "\nPlease supply a netmask in the form of a.b.c.d/n where n is the netmask.\n"
					exit 1
				end
			end

			o.on "-a", "--approved [LIST]", "A (optional) comma separated list of hosts that are approved" do |a|
				@config[:approved] = a.split ","
				if @config[:approved].nil?
					puts "Please specify the approved server list as a comma separated string"
					puts "Example: -a server1.example.com,server2.example.com,server3.another.domain.com"
					exit 1
				end

			end

			o.on "-p", "--port NUMBER", "A port number to scan for connectivity. Specify multiple times for multiple ports. Default is 80." do |p|
				if @config[:ports].nil?
					@config[:ports] = [p]
				else
					@config[:ports] << p
				end
			end
			
			o.on "-o", "--output FILENAME", "Filename to write report to (netscan.log is the default)" do |o|
				@config[:outfile] = o
			end

			o.on "-t", "--test", "Test for an HTTP response in addition to an open port" do |t|
				@config[:test_for_http] = true
			end
			
		
		end
		parser.parse!(args)

		# If network isn't set then we can't continue
		if @config[:network].nil?
			puts "\nYou must define a network to scan with -n or --network for the script the function.\n\n"
			exit 1
		end
		
		# Set port defaults if they were not specified
		if @config[:ports].nil?
			@config[:ports] = [80]
		end

		# Set approved list as empty array if not specified
		@config[:approved] = [] if config[:approved].nil?

		# Open output file
		@logfile = File.open @config[:outfile], "w"

	end

	def log_it(host, ports)
		@output <<  [Time.now, host, ports.join(",")]
	end

	def test_ports
		[]
	end

	def scan
		cidr = NetAddr::CIDR.create @config[:network]

		first = cidr.first
		last  = cidr.last

		cidr.enumerate.each do |addr|
			# Skip the first and last address in the range, assuming they are network number (i.e. 192.168.1.0) and broadcast (192.168.1.255)
 			next if (addr == first) or (addr == last)

			# Returns an array of Port class objects
			p = test_ports addr

			if !p.empty?
				# There's something to log...
				log_it addr, p
				
			end
			
		end
	end

	def report
		Terminal::Table.new :headings => ['Time','Host','Ports (* indicates HTTP response)'], :rows => @output
	end
		

end

netscan = Netscan.new ARGV
pp netscan.config
exit

netscan.scan
puts netscan.report
