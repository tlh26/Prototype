"""
Answers: "Where exactly did this evidence originate?"
For example:
    Provenance
│
├── source_type: INCUS
├── source_host: incus-host-01
├── source_path: /var/log/incus/...
├── source_identifier
├── acquisition_method
└── acquired_at
Represents the lineage and history of an event or resource.
        Class: Provenance
        Attributes: provenance_id
                    source_id
                    target_id
                    relationship_type
                    timestamp
                    context
"""
