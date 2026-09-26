"""Describes the technical context in which evidence was acquired and processed.
    Class: EvidenceMetadata
    Attributes: evidence_id
                source
                schema_version
                collector
                collector_version
                parser
                parser_version
                collection_timestamp
                original_timestamp
EvidenceMetadata should be immutable after the record is finalised."""


class EvidenceMetadata:
    def __init__(
        self,
        evidence_id,
        source,
        schema_version,
        collector,
        collector_version,
        parser,
        parser_version,
        collection_timestamp,
        original_timestamp,
    ):
        self.evidence_id = evidence_id
        self.source = source
        self.schema_version = schema_version
        self.collector = collector
        self.collector_version = collector_version
        self.parser = parser
        self.parser_version = parser_version
        self.collection_timestamp = collection_timestamp
        self.original_timestamp = original_timestamp
