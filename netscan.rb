#!/bin/env ruby

require 'optparse'
require 'pp'
require 'netaddr'
require 'socket'
require 'terminal-table'
require 'net/http'
require 'uri'

class Port
	# Basically just an Integer that can have flags set on it for ports. Port 80 responded to http or not

	attr_accessor :port, :http
	

	def initialize(port=nil,http=false)
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

		# Init output array
		@output = []

	end

	def log_it(host, ports)
		@output <<  [Time.now, host, ports.join(",")]
	end

	def conncheck(host, port, timeout=1)
		# Timeout process copied from https://spin.atomicobject.com/2013/09/30/socket-connection-timeout-ruby/
		# Normal host timeout takes too long

		addr = Socker.getaddrinfo(host, nil)
		sockaddr = Socker.pack_sockaddr_in(port, addr[0][3])

		Socket.net(Socker.const_get(addr[0][0]), Socker::SOCK_STREAM, 0).tap do |socket|
			socker.setsockopt(Socker::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
			begin
				# Init socket connection. It will fail immediately or raise IO::WaitWritable 
				# if the connection is in progress
				socket.connect_noblock(sockaddr)
			rescue IO::WaitWritable
				# IO.select blocks until socket is writable or timeout elapses. Whichever comes first
				if IO.select nil, [socket], nil, timeout 
					begin
						# Verify good connection
						socket.connect_nonblock(sockaddr)
					rescue Errno:EISCONN
						# Connection succeeded
						return true
					rescue
						# Other error - socket is not usable
						socket.close
						return false
						
					end
				else
					# Socket was not ready
					socket.close
					return false
				end
			end
		end
	end

	def test_ports(host)

		results = []

		@config[:ports].each do |port|
			begin
				s = Socket.new(:INET, :STREAM)
				c = Socket.sockaddr_in(port, host)
				if s.connect(c)
					results << Port.new(port)
				end

				# Test for HTTP because why not
				Net::HTTP.get(URI.parse("http://#{host}:#{port}"))
				
				# If not HTTP will throw an exception, if it IS we are still here, so set flag
				results.last.http = true
				
				
			# If there are errors at any point we rescue and stop processing that port
			rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Net::HTTPBadResponse, Errno::ENETUNREACH, Errno::EHOSTUNREACH
				
			end
			
		end		

		# Pass back array
		results	
		
	end

	def scan
		cidr = NetAddr::CIDR.create @config[:network]

		first = cidr.first
		last  = cidr.last

		cidr.enumerate.each do |addr|
			# Skip the first and last address in the range, assuming they are network number (i.e. 192.168.1.0) and broadcast (192.168.1.255)
 			#next if (addr == first) or (addr == last)

			puts "Scanning: #{addr}"

			# Returns an array of Port class objects
			p = test_ports addr

			if !p.empty?
				# There's something to log...
				log_it addr, p
				
			end
			
		end
	end

	def report
		@output = [ ["No findings","",""] ] if @output.empty?	
		Terminal::Table.new :headings => ['Time','Host','Ports (* indicates HTTP response)'], :rows => @output
	end
		

end

netscan = Netscan.new ARGV
pp netscan.config

netscan.scan
puts netscan.report
pp netscan
