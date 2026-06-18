require 'rfc5424/formatter'
require 'syslog'

module Fluent
  module Plugin
    class FormatterSyslogRFC5424 < Formatter
      Fluent::Plugin.register_formatter('syslog_rfc5424', self)

      config_param :rfc6587_message_size, :bool, default: true
      config_param :hostname_field, :string, default: "hostname"
      config_param :app_name_field, :string, default: "app_name"
      config_param :proc_id_field, :string, default: "proc_id"
      config_param :message_id_field, :string, default: "message_id"
      config_param :structured_data_field, :string, default: "structured_data"
      config_param :log_field, :string, default: "log"
      config_param :facility_field, :string, default: "facility"
      config_param :severity_field, :string, default: "severity"

      DEFAULT_FACILITY = "user"
      DEFAULT_SEVERITY = "info"

      FACILITIES_MAP = {
      }

      def configure(conf)
        super
        @hostname_field_array = @hostname_field.split(".")
        @app_name_field_array = @app_name_field.split(".")
        @proc_id_field_array = @proc_id_field.split(".")
        @message_id_field_array = @message_id_field.split(".")
        @structured_data_field_array = @structured_data_field.split(".")
        @log_field_array = @log_field.split(".")
        @facility_field_array = @facility_field.split(".")
        @severity_field_array = @severity_field.split(".")
      end

      def format(tag, time, record)
        msg_id = record.dig(*@message_id_field_array) || "unknown message id"
        log.debug("#{msg_id} - Record: #{record.map { |k, v| "#{k}=#{v}" }.join('&')}")

        msg = RFC5424::Formatter.format(
          priority: priority_from_facility_and_severity(record),
          log: record.dig(*@log_field_array) || "-",
          timestamp: time,
          hostname: record.dig(*@hostname_field_array) || "-",
          app_name: record.dig(*@app_name_field_array) || "-",
          proc_id: record.dig(*@proc_id_field_array) || "-",
          msg_id: record.dig(*@message_id_field_array) || "-",
          sd: record.dig(*@structured_data_field_array) || "-"
        )

        log.debug("#{msg_id} - RFC 5424 Message: #{msg}")

        return msg + "\n" unless @rfc6587_message_size

        msg.bytesize.to_s + ' ' + msg
      end

      def priority_from_facility_and_severity(record)
        msg_id = record.dig(*@message_id_field_array) || "unknown message id"
        facility = record.dig(*@facility_field_array) || DEFAULT_FACILITY
        severity = record.dig(*@severity_field_array) || DEFAULT_SEVERITY

        begin
          severity_int = Syslog.const_get("LOG_#{severity.upcase}")
        rescue NameError
          severity_int = Syslog.const_get("LOG_ALERT")
        end
        log.debug("#{msg_id} - Severity: #{severity} (#{severity_int})")

        begin
          facility_int = Syslog.const_get("LOG_#{facility.upcase}")
        rescue NameError
          facility_int = Syslog.const_get("LOG_#{DEFAULT_FACILITY.upcase}")
        end
        log.debug("#{msg_id} - Facility: #{facility} (#{facility_int})")

        return (facility_int * 8) + severity_int
      end
    end
  end
end
