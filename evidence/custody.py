"""
CustodyEntry: Represents one evidence handling event
ChainOfCustody: Contains a list of custody entries

    Class: CustodyEntry
    Attributes: custody_id
                timestamp
                actor
                action
                reason
                system
    For example: 10:00  COLLECTED
                10:01  HASHED
                10:02  PARSED
                10:03  NORMALISED
                10:04  STORED
                10:10  CORRELATED

    Class: ChainOfCustody
    Methods: addEntry()
            getHistory()
            lastAction()
    Attributes: custody_id
"""
