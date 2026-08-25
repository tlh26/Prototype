"""
Actor domain model.

Represents the entity responsible for an event.
        Class: Actor
        Attributes: actor_id
                    actor_type
                    username
                    ip_address
                    host
                    role
                    actor_name (?)
                    actor_hash
                    platform (?)
                    platform_user_id (?)
        Possible actor types include:
            - Human user
            - Service account
            - System process
            - External system (e.g., API client)
            - Unknown actor
"""