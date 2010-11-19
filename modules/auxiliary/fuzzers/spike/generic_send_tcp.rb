##
# $Id: ssh_version_corrupt.rb 9212 2010-05-03 17:13:09Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rubygems'
require 'rspike'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Fuzzer

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Generic send TCP',
			'Description'    => %q{
				This module uses a SPIKE file to fuzz a TCP server.
			},
			'Author'         => [ 'dougsko' ],
			'License'        => MSF_LICENSE,
    		'Version'        => '0.0.1'
		))
		register_options([
			OptString.new('SPIKEFILE', [true, 'Specify a SPIKE file to use'])
		], self.class)
	end

    def make_connection
        begin
            connect
        rescue ::Interrupt
            raise $!
        rescue ::Rex::ConnectionRefused
            print_status("Server shut down")
            exit
        end
    end

    def send_pkt(pkt)
        begin
            sock.put(pkt)
            puts sock.get
        rescue
            sleep 0.1
        end
    end

	def run
        rspike = RSpike.new
        rspike.generate(datastore["SPIKEFILE"]) do |so|
            print_status "Fuzzing variables #{so.fuzzvarnum.to_s}:#{so.fuzzstrnum.to_s}"
            make_connection
            send_pkt(so.string)
            disconnect
        end
    end
end
