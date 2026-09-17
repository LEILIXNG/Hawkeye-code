package controllers

import services.UserRepository

class UserController {
  def show(id: String): String = {
    UserRepository.findUser(id)
  }

  def showSafe(id: String): String = {
    UserRepository.findUserSafe(id)
  }
}
