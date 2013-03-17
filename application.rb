require 'rubygems'
require 'pcaplet'
require 'rainbow'


#status_filters = /4\d\d.*/ #400 

http_packets_dump = Pcaplet.new('-s 2000')

HTTP_REQUEST  = Pcap::Filter.new('tcp and dst port 80', http_packets_dump.capture)
HTTP_RESPONSE = Pcap::Filter.new('tcp and src port 80', http_packets_dump.capture)

http_packets_dump.add_filter(HTTP_REQUEST | HTTP_RESPONSE)

http_packets_dump.each do |packet| 
  case packet
      when HTTP_REQUEST
        if packet.tcp_data and packet.tcp_data =~ /^GET\s+(\S+)/
          path = $1
          host = packet.dst.to_s
          host << ":#{packet.dst_port}" if packet.dport != 80
          s = "#{packet.src}:#{packet.sport} > " + "GET http://#{host}#{path}".color(:green).bright
        end
      when HTTP_RESPONSE
        if packet.tcp_data and packet.tcp_data =~ /^(HTTP\/.*)$/# and not packet.tcp_data =~ status_filters
          status = $1
          s = "#{packet.dst}:#{packet.dport} < #{status}"
        end
  end

  puts s unless s.nil?
end
