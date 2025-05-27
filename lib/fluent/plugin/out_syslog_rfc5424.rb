require 'fluent/plugin/output'

module Fluent
  module Plugin
    class OutSyslogRFC5424 < Output
      Fluent::Plugin.register_output('syslog_rfc5424', self)

      helpers :socket, :formatter
      DEFAULT_FORMATTER = "syslog_rfc5424"
      
      DEFAULT_CONNECT_TIMEOUT = 10
      DEFAULT_SEND_TIMEOUT = 15
      DEFAULT_RECV_TIMEOUT = 15
      DEFAULT_LINGER_TIMEOUT = 0

      config_param :host, :string
      config_param :port, :integer
      config_param :transport, :string, default: "tls"
      config_param :insecure, :bool, default: false
      config_param :trusted_ca_path, :string, default: nil
      config_param :connect_timeout, :integer, default: DEFAULT_CONNECT_TIMEOUT
      config_param :send_timeout, :integer, default: DEFAULT_SEND_TIMEOUT
      config_param :recv_timeout, :integer, default: DEFAULT_RECV_TIMEOUT
      config_param :linger_timeout, :integer, default: DEFAULT_LINGER_TIMEOUT
      config_section :format do
        config_set_default :@type, DEFAULT_FORMATTER
      end

      def configure(config)
        super
        @sockets = {}
        @formatter = formatter_create
      end

      def multi_workers_ready?
        true
      end

      def write(chunk)
        socket = find_or_create_socket(@transport.to_sym, @host, @port)
        tag = chunk.metadata.tag
        chunk.each do |time, record|
          begin
            socket.write_nonblock @formatter.format(tag, time, record)
            IO.select(nil, [socket], nil, 1) || raise(StandardError.new "ReconnectError")
          rescue => e
            @sockets.delete(socket_key(@transport.to_sym, @host, @port))
            socket.close
            raise
          end
        end
      end

      def close
        super
        @sockets.each_value { |s| s.close }
        @sockets = {}
      end

      private

      def find_or_create_socket(transport, host, port)
        socket = find_socket(transport, host, port)
        return socket if socket

        @sockets[socket_key(transport, host, port)] = socket_create(transport.to_sym, host, port, socket_options)
      end

      def socket_options
        if @transport == 'udp'
          { connect: true }
        elsif @transport == 'tls'
          { insecure: @insecure, verify_fqdn: !@insecure, cert_paths: @trusted_ca_path , connect_timeout: @connect_timeout, send_timeout: @send_timeout, recv_timeout: @recv_timeout, linger_timeout: @linger_timeout }
        else
          {}
        end
      end

      def socket_key(transport, host, port)
        "#{host}:#{port}:#{transport}"
      end

      def find_socket(transport, host, port)
        @sockets[socket_key(transport, host, port)]
      end
    end
  end
end
