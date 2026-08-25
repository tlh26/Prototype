"""
Conceptually: 
class EvidenceRecord(BaseModel):
    evidence_id: str

    event_type: EventType
    event_category: EvidenceCategory

    timestamp: datetime

    source: EvidenceSource

    metadata: EvidenceMetadata

    tenant: TenantContext | None

    actor: Actor | None

    resource: Resource | None

    provenance: Provenance

    integrity: IntegrityInformation

    custody: ChainOfCustody

    relationships: list[EvidenceRelationship]

    raw_data: dict

"""