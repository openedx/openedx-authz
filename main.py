"""
This is a simple example of how to use Casbin to enforce policies.
"""

from casbin import Enforcer

# policy_file = "simple-policy.csv"
# model_file = "simple-model.conf"

policy_file = "authz.policy"
model_file = "model.conf"

enforcer = Enforcer(model_file, policy_file)

enforcer.load_policy()


# Complex Example

# Get permissions for a user
print(enforcer.get_permissions_for_user("role:library_admin"))

# # Get permissions for a user in a specific domain
# print(enforcer.get_permissions_for_user_in_domain("alice", "lib:math_101"))

# Get implicit permissions for a user
print(enforcer.get_implicit_permissions_for_user("user:alice_admin", "lib:math_101"))
print(enforcer.get_implicit_permissions_for_user("user:frank_global"))

# Get roles for a user in a specific domain
print(enforcer.get_roles_for_user_in_domain("user:alice_admin", "lib:math_101"))
print(enforcer.get_roles_for_user_in_domain("user:frank_global", "*"))

# Get all roles
print(enforcer.get_role_manager().get_roles("user:alice_admin", "lib:math_101"))

# Print all roles
print(enforcer.get_role_manager().print_roles())
