#!/bin/env ruby

require 'optparse'
require 'pp'
require 'netaddr'
require 'socket'
require 'terminal-table'
require 'net/http'
require 'uri'
require 'resolv'

DEBUG = false

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

	# Allow the configuration to be directly read
	attr_reader :config


	def initialize(args)

		# Init options hash
		@config = {:outfile 	  => "netscan.log", 
		           :test_for_http => false,
			   :verbose       => false }

		# Parse command line options
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

			o.on("-v", "--[no-]verbose", "Run verbosely") do |v|
				@config[:verbose] = true
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


		# Init output array
		@output = []

		# Load hash of IP addresses that are allowed to make positive hits
		load_approved

	end

	def load_approved

		# Init hash
		@approved = {}

		# Resolve each host and store all as IP addresses in a hash for easy lookup	
		@config[:approved].each do |host|
			begin
				ip = Resolv.getaddress host
				@approved[ip] = host
			rescue
				# If an error was thrown the entry did not resolve via DNS. Skip it, and hope the user spells it right next time
			end
					
		end	

	end

	def log_it(host, ports)

		# We're storing the output as a three element array so it can be sent to the table object and printed.

		hoststring = host
		begin
			hoststring = hoststring + "(#{Resolv.getname host})"
		rescue
			# If we hit this block, could not resolve IP
		end
		@output <<  [Time.now, hoststring, ports.join(",")]
	end

	def conncheck(host, port, timeout=0.1)
		# Using the method to override the system timeout. Most systems wait several seconds for a TCP connection to be established which makes for a long scan.

		# Timeout process copied from https://spin.atomicobject.com/2013/09/30/socket-connection-timeout-ruby/
		# Normal host timeout takes too long

		# Get information needed to open socket
		addr = Socket.getaddrinfo(host, nil)
		sockaddr = Socket.pack_sockaddr_in(port, addr[0][3])

		Socket.new(Socket.const_get(addr[0][0]), Socket::SOCK_STREAM, 0).tap do |socket|
			socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
			begin
				# Init socket connection. It will fail immediately or raise IO::WaitWritable 
				# if the connection is in progress
				socket.connect_nonblock(sockaddr)
			rescue IO::WaitWritable
				# IO.select blocks until socket is writable or timeout elapses. Whichever comes first
				if IO.select nil, [socket], nil, timeout 
					begin
						# Verify good connection
						socket.connect_nonblock(sockaddr)
						puts "---------------> Hit!" if @config[:verbose]
					rescue Errno::EISCONN
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
			rescue
				# Other Network I/O error
				socket.close
				return false
				
			end
		end
	end

	def test_ports(host)

		results = []

		# For a single host, scan each port using conncheck
		@config[:ports].each do |port|

			puts "---> Port #{port}" if @config[:verbose]

			if conncheck(host, port)	
				# Store the positive result
				results << Port.new(port)
				begin

					# Test for HTTP because why not
					Net::HTTP.get(URI.parse("http://#{host}:#{port}"))
					
					# If not HTTP will throw an exception, if it IS we are still here, so set flag
					results.last.http = true
					puts "---------------> HTTP Response" if @config[:verbose]
				
				rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Net::HTTPBadResponse, Errno::ENETUNREACH, Errno::EHOSTUNREACH
					# If we're here then the http get failed, so nothing to add to the Port object

				end
			end
		end		

		# Pass back array
		results	
		
	end

	def scan

		# Create an object to respresent the subnet
		cidr = NetAddr::CIDR.create @config[:network]

		first = cidr.first
		last  = cidr.last

		cidr.enumerate.each do |addr|
			# Skip the first and last address in the range, assuming they are network number (i.e. 192.168.1.0) and broadcast (192.168.1.255)
 			#next if (addr == first) or (addr == last)

			puts "Scanning: #{addr}" if @config[:verbose]

			# Skip this host if it is on the approved list
			if @approved.keys.include? addr			
				puts "This host is approved, skipping" if @config[:verbose]
				next
			end

			# Returns an array of Port class objects that were "hits"
			p = test_ports addr

			if !p.empty?
				# There's something to log...
				log_it addr, p
				
			end
			
		end
	end

	def report

		# Dump the array we are keeping of results into Terminal::Table so it's pretty

		@output = [ ["No findings","",""] ] if @output.empty?	
		Terminal::Table.new :headings => ['Time','Host','Ports (* indicates HTTP response)'], :rows => @output
	end
		

end

#### A quickie method to verify the necessary ruby libraries (gems) are installed
def gem_available?(name)

	# Returns an object if found
	Gem::Specification.find_by_name(name)

rescue Gem::LoadError

	# And throws an exception (sigh) if not
	false

rescue

	# Old pre-2 method that's only available if Gem::Specification isn't
	Gem.available?(name)

end

# Quick check that libs are available
g = []
["netaddr","terminal-table"].each do |gem|
	g << gem if !gem_available?(gem)
end

if !g.empty?
	# Crap, missing libs
	puts
	puts "Hi there!"
	puts
	puts "In order for this script to run it requires some libraries (gem files). Please install the following libraries"
	puts "by executing \"gem install libraryname\" for each library mentioned below:"
	puts
	g.each do |gem|
		puts "     #{gem}"
	end
	puts
	puts "The script will execute normally once that's done. Sorry for the inconvenience!"
	puts
	exit 1
end

# Main

# Create a netscan object and pass it command line parameters
netscan = Netscan.new ARGV

# For debugging, displays the final config after parsing command line
pp netscan.config if DEBUG

# Do actual scan
netscan.scan

# Get Report generated from collected data
report = netscan.report

# Print to screen
puts report

# Print to file
# Open output file
begin
	out = File.open(netscan.config[:outfile], "w")
	out.puts report
	puts "Report written to #{netscan.config[:outfile]}"
rescue => e
	puts "Error writing logfile. Error is: #{e.message}"
end

# Dump netscan object for debugging if enabled
pp netscan if DEBUG
