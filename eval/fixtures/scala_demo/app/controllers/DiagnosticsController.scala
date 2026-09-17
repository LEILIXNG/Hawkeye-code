package controllers

import services.CommandService

class DiagnosticsController {
  def ping(host: String): String = {
    CommandService.runPing(host)
    "ok"
  }

  def pingSafe(host: String): String = {
    CommandService.runPingSafe(host)
    "ok"
  }
}
