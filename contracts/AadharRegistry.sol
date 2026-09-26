// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract AadhaarRegistry {

    struct IdentityRecord {
        string  aadhaarId;
        string  nameHash;
        string  identityHash;
        string  signature;
        uint256 timestamp;
        bool    exists;
    }

    address public authority;
    mapping(string => IdentityRecord) private records;
    string[] public registeredIds;

    event IdentityRegistered(
        string  aadhaarId,
        string  identityHash,
        uint256 timestamp
    );

    constructor() {
        authority = msg.sender;
    }

    modifier onlyAuthority() {
        require(msg.sender == authority, "Not authorized");
        _;
    }

    function registerIdentity(
        string memory aadhaarId,
        string memory nameHash,
        string memory identityHash,
        string memory signature
    ) public onlyAuthority {
        require(!records[aadhaarId].exists, "Aadhaar ID already registered");
        records[aadhaarId] = IdentityRecord({
            aadhaarId    : aadhaarId,
            nameHash     : nameHash,
            identityHash : identityHash,
            signature    : signature,
            timestamp    : block.timestamp,
            exists       : true
        });
        registeredIds.push(aadhaarId);
        emit IdentityRegistered(aadhaarId, identityHash, block.timestamp);
    }

    function getIdentityProof(string memory aadhaarId)
        public view
        returns (string memory, string memory, string memory, uint256, bool)
    {
        IdentityRecord memory record = records[aadhaarId];
        return (
            record.identityHash,
            record.signature,
            record.nameHash,
            record.timestamp,
            record.exists
        );
    }

    function isRegistered(string memory aadhaarId)
        public view returns (bool)
    {
        return records[aadhaarId].exists;
    }

    function getTotalRegistered() public view returns (uint256) {
        return registeredIds.length;
    }
}