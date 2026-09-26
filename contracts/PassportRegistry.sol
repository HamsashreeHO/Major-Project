// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract PassportRegistry {

    struct PassportApplication {
        uint256 appId;
        string  aadhaarId;
        string  applicantName;
        string  status;
        string  identityHash;
        uint256 timestamp;
    }

    address public authority;
    uint256 public totalApplications;
    mapping(uint256 => PassportApplication) public applications;
    mapping(string  => uint256)             public aadhaarToAppId;

    event PassportApplied(
        uint256 appId,
        string  aadhaarId,
        string  applicantName,
        string  status,
        uint256 timestamp
    );

    constructor() {
        authority         = msg.sender;
        totalApplications = 0;
    }

    function submitApplication(
        string memory aadhaarId,
        string memory applicantName,
        string memory status,
        string memory identityHash
    ) public returns (uint256) {
        totalApplications++;
        uint256 appId = totalApplications;
        applications[appId] = PassportApplication({
            appId        : appId,
            aadhaarId    : aadhaarId,
            applicantName: applicantName,
            status       : status,
            identityHash : identityHash,
            timestamp    : block.timestamp
        });
        aadhaarToAppId[aadhaarId] = appId;
        emit PassportApplied(
            appId,
            aadhaarId,
            applicantName,
            status,
            block.timestamp
        );
        return appId;
    }

    function getApplication(uint256 appId)
        public view
        returns (string memory, string memory, string memory, uint256)
    {
        PassportApplication memory app = applications[appId];
        return (
            app.applicantName,
            app.aadhaarId,
            app.status,
            app.timestamp
        );
    }

    function getTotalApplications() public view returns (uint256) {
        return totalApplications;
    }
}