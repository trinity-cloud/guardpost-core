# This file makes Python treat the 'graph_queries' directory as a package.
# You can optionally import specific query functions here for easier access elsewhere,
# but it's often cleaner to import directly from the service-specific modules.

# Example (optional):
# from .s3_graph_queries import check_public_acls
# from .iam_graph_queries import check_roles_with_broad_trust

# __all__ = [
#     "check_public_acls",
#     "check_roles_with_broad_trust",
# ] 