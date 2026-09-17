class UserController {
    @GetMapping("/users/{id}")
    fun show(id: String): String {
        return UserRepository().findUser(id)
    }

    @GetMapping("/users/safe/{id}")
    fun showSafe(id: String): String {
        return UserRepository().findUserSafe(id)
    }
}
