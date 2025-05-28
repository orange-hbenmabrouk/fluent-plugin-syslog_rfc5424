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
      DEFAULT_KEEPALIVE_TIMEOUT = 30

      config_param :host, :string
      config_param :port, :integer
      config_param :transport, :string, default: "tls"
      config_param :insecure, :bool, default: false
      config_param :trusted_ca_path, :string, default: nil

      config_param :connect_timeout, :integer, default: DEFAULT_CONNECT_TIMEOUT
      config_param :send_timeout, :integer, default: DEFAULT_SEND_TIMEOUT
      config_param :recv_timeout, :integer, default: DEFAULT_RECV_TIMEOUT
      config_param :linger_timeout, :integer, default: DEFAULT_LINGER_TIMEOUT

      config_param :keepalive, :bool, default: true
      config_param :keepalive_timeout, :integer, default: DEFAULT_KEEPALIVE_TIMEOUT

      config_section :format do
        config_set_default :@type, DEFAULT_FORMATTER
      end

      def configure(config)
        super
        @sockets = {}
        @socket_last_used = {}
        @formatter = formatter_create
        @mutex = Mutex.new
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

        # Update last used time for keepalive tracking
        @mutex.synchronize do
          @socket_last_used[socket_key(@transport.to_sym, @host, @port)] = Time.now
        end
      end

      def close
        super
        @mutex.synchronize do
          @sockets.each_value { |s| s.close rescue nil }
          @sockets = {}
          @socket_last_used = {}
        end
      end

      private

      def find_or_create_socket(transport, host, port)
        @mutex.synchronize do
          key = socket_key(transport, host, port)
          socket = @sockets[key]
          last_used = @socket_last_used[key]

          if socket && @keepalive && last_used && (Time.now - last_used) > @keepalive_timeout
            log.debug "Socket keepalive timeout reached, recreating socket connection to #{transport}://#{host}:#{port}"
            socket.close rescue nil
            @sockets.delete(key)
            @socket_last_used.delete(key)
            socket = nil
          end

          # Create new socket if needed
          unless socket
            socket = socket_create(transport.to_sym, host, port, socket_options)
            @sockets[key] = socket
            @socket_last_used[key] = Time.now
            log.debug "Created new socket connection to #{transport}://#{host}:#{port}"
          end

          socket
        end
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
    end
  end
end
