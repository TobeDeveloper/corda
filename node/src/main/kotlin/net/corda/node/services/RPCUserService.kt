package net.corda.node.services

import com.typesafe.config.Config
import net.corda.core.crypto.SecureHash
import net.corda.core.flows.FlowLogic
import net.corda.node.services.config.getListOrElse
import java.util.*

/**
 * Service for retrieving [User] objects representing RPC users who are authorised to use the RPC system. A [User]
 * contains their login username and password along with a set of permissions for RPC services they are allowed access
 * to. These permissions are represented as [String]s to allow RPC implementations to add their own permissioning.
 */
interface RPCUserService {
    fun getUser(username: String): User?
    val users: List<User>

    /**
     * TODO The system user is used by the web api until we implement web auth properly
     * The password should be unique per process, so in theory only the node itself should have access to it.
     */
    fun addSystemUserPermission(permission: String)
    companion object {
        val systemUserUsername = "~systemUser"
        val systemUserPassword: String = SecureHash.randomSHA256().toString()
    }
}

// TODO Store passwords as salted hashes
// TODO Or ditch this and consider something like Apache Shiro
class RPCUserServiceImpl(config: Config) : RPCUserService {

    private val _users: HashMap<String, User>

    init {
        val defaultUsers = listOf(User(RPCUserService.systemUserUsername, RPCUserService.systemUserPassword, setOf()))
        val users = config.getListOrElse<Config>("rpcUsers") { emptyList() }
                .map {
                    val username = it.getString("user")
                    require(username.matches("\\w+".toRegex())) { "Username $username contains invalid characters" }
                    val password = it.getString("password")
                    val permissions = it.getListOrElse<String>("permissions") { emptyList() }.toSet()
                    User(username, password, permissions)
                }
        _users = HashMap((defaultUsers + users).associateBy(User::username))
    }

    override fun getUser(username: String): User? = _users[username]

    override val users: List<User> get() = _users.values.toList()

    override fun addSystemUserPermission(permission: String) {
        _users.computeIfPresent(RPCUserService.systemUserUsername) { _username, systemUser ->
            systemUser.copy(permissions = systemUser.permissions + setOf(permission))
        }
    }
}

data class User(val username: String, val password: String, val permissions: Set<String>) {
    override fun toString(): String = "${javaClass.simpleName}($username, permissions=$permissions)"
}

fun <P : FlowLogic<*>> startFlowPermission(clazz: Class<P>) = "StartFlow.${clazz.name}"
inline fun <reified P : FlowLogic<*>> startFlowPermission(): String = startFlowPermission(P::class.java)
