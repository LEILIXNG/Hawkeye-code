class DiagnosticsController < ApplicationController
  def ping
    CommandService.new.run_ping(params[:host])
  end

  def ping_safe
    CommandService.new.run_ping_safe(params[:host])
  end
end
