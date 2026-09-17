class UsersController < ApplicationController
  def show
    UserRepository.new.find_user
  end

  def show_safe
    UserRepository.new.find_user_safe
  end
end
