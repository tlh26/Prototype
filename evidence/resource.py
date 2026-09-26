"""
Resource domain model.

Represents the cloud object involved in the event.
        Class: Resource
        Attributes: resource_id
                    resource_type
                    resource_name
                    resource_hash
                    platform
                    platform_resource_id
                    parent_resource_id
        For Incus:
            Instance
            Container
            Virtual Machine
            Project
            Network
            Storage
            Image
            Snapshot

Relationship engine can later identify:
- same resource
- same project
- parent-child resource
- resource migration
- resource lifecycle
"""
