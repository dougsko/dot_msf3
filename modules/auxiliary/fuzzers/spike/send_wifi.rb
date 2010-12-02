require 'msf/core'
require 'rubygems'
require 'rspike'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Lorcon2
	include Msf::Auxiliary::Fuzzer

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Fuzz wifi with SPIKE and Lorcon',
			'Description'    => %q{
				This is a generic wifi fuzzer that uses SPIKE and Lorcon.
                It requires the 'rspike' gem and Lorcon.
                Just set up a SPIKE file to define the packet you want to
                send and fire it off.
			},
			'Author'         => [ 'dougsko' ],
			'License'        => MSF_LICENSE,
    		'Version'        => '0.0.1'
		))
		register_options([
			OptString.new('SPIKEFILE', [true, 'Specify a SPIKE file to use']),
            OptString.new('ADDR_DST', [ true,  "The MAC address of the target system",'FF:FF:FF:FF:FF:FF']),
            OptString.new('PING_HOST', [ false,  "Ping the wired address of the target host"])
		], self.class)
	end

    def ping_check
        1.upto(3) do |i|
            x = `ping -c 1 -n #{datastore['PING_HOST']}`
            return true if x =~ /1 received/
            if (i > 1)
                print_status("Host missed a ping response...")
            end
        end
        false
    end

	def run
        open_wifi
        frames = []

        rspike = RSpike.new
        rspike.generate(datastore["SPIKEFILE"]) do |so|
            if (datastore['PING_HOST'])
                if (frames.length >= 5)
                    frames.shift
                    frames.push(so.string)
                else
                    frames.push(so.string)
                end

                1.upto(10) do
                    wifi.write(so.string)
                    if (not ping_check)
                        frames.each do |f|
                            print_status "****************************************"
                            print_status f.inspect
                        end
                    end
                end
            else
                        
            print_status "Fuzzing variables #{so.fuzzvarnum.to_s}:#{so.fuzzstrnum.to_s}"

                wifi.write(so.string)
            end
        end
    end
end
