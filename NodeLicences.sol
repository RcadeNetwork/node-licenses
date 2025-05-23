// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC721Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import {ERC721BurnableUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721BurnableUpgradeable.sol";
import {ERC721EnumerableUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";


contract NodeLicences is Initializable, ERC721Upgradeable, ERC721EnumerableUpgradeable, AccessControlUpgradeable, ERC721BurnableUpgradeable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    event TokensClaimed(address indexed caller, uint256[] tokenIdsForProof, uint256[] tokenIdsForMint, uint timestamp);
    event MerkleRootUpdated(address indexed caller, bytes32 indexed oldMerkleRoot, bytes32 indexed newMerkleRoot, uint timestamp);
    event TransferAllowedStatusUpdated(address indexed caller, bool indexed oldStatus, bool indexed newStatus, uint timestamp);

    struct ReservationDetails {
        uint startTokenId;
        uint endTokenId;
    }
    
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 public immutable PAUSER_ROLE = keccak256("PAUSER_ROLE");
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 public immutable UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    
    string private _baseTokenURI;
    bool public _isTransferAllowed;

    bytes32 public _merkleRoot;
    mapping(uint256 tokenId => bool isBurned) public _isBurned;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(bytes32 merkleRoot, string calldata baseTokenURI)
        initializer public
    {
        __ERC721_init("NodeLicences", "NL");
        __ERC721Enumerable_init();
        __AccessControl_init();
        __ERC721Burnable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _merkleRoot = merkleRoot;
        _baseTokenURI = baseTokenURI;
        
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
    }

    function transferOwnership(address newOwner) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newOwner != address(0), "NodeLicences: New owner is null address");

        _revokeRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _revokeRole(PAUSER_ROLE, msg.sender);
        _revokeRole(UPGRADER_ROLE, msg.sender);

        _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
        _grantRole(PAUSER_ROLE, newOwner);
        _grantRole(UPGRADER_ROLE, newOwner);
    }

    function claimToken(bytes32[] calldata proof, uint256[] calldata tokenIdsForProof, uint256[] calldata tokenIdsForMint) public whenNotPaused nonReentrant {
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(msg.sender, tokenIdsForProof))));
        require(MerkleProof.verify(proof, _merkleRoot, leaf), "Invalid proof");

        (uint[] memory tokenIds, uint tokenIdsLength) = _getValidTokenIdsForMint(tokenIdsForProof, tokenIdsForMint);

        for (uint256 i; i < tokenIdsLength; i++) {
            require(!_isBurned[tokenIds[i]], "NodeLicences: Token is already burned");
           
            address currentOwner = _ownerOf(tokenIds[i]);

            if (currentOwner == msg.sender){
                continue;
            }
            else if (currentOwner != address(0)){
                revert("NodeLicences: Token is owned by another address");
            }
            _mint(msg.sender, tokenIds[i]);
        }
        emit TokensClaimed(msg.sender, tokenIdsForProof, tokenIdsForMint, block.timestamp);
    }

    function _getValidTokenIdsForMint(uint256[] calldata tokenIdsForProof, uint256[] calldata tokenIdsForMint) private pure returns(uint[] memory, uint) {
        bool isTokenIdsForMintEmpty = tokenIdsForMint.length == 0;
        if (!isTokenIdsForMintEmpty) {
            _checkValidTokenIdsForMint(tokenIdsForProof, tokenIdsForMint);
            return (tokenIdsForMint, tokenIdsForMint.length);
        }
        return (tokenIdsForProof, tokenIdsForProof.length);
    }

    function _baseURI() internal view override returns (string memory) {
        return _baseTokenURI;
    }

    function setBaseURI(string memory newBaseURI) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _baseTokenURI = newBaseURI;
    }

    function updateTransferAllowedStatus(bool updatedStatus) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(updatedStatus != _isTransferAllowed, "NodeLicences: Cannot update to same status");
        bool oldStatus = _isTransferAllowed;
		_isTransferAllowed = updatedStatus;
        emit TransferAllowedStatusUpdated(msg.sender, oldStatus, updatedStatus, block.timestamp);
	}

    function updateMerkleRoot(bytes32 newMerkleRoot) public onlyRole(DEFAULT_ADMIN_ROLE) {
        bytes32 oldMerkleRoot = _merkleRoot;
        _merkleRoot = newMerkleRoot;
        emit MerkleRootUpdated(msg.sender, oldMerkleRoot, newMerkleRoot, block.timestamp);
    }

    function transferFrom(address from, address to, uint256 tokenId) public override(ERC721Upgradeable, IERC721) whenNotPaused {
        _checkIsTransferAllowed();
        super.transferFrom(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public override(ERC721Upgradeable, IERC721) whenNotPaused {
        _checkIsTransferAllowed();
        super.safeTransferFrom(from, to, tokenId, data);
    }

    function burn(uint256 tokenId) public override whenNotPaused {
        _isBurned[tokenId] = true;
        super.burn(tokenId);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        onlyRole(UPGRADER_ROLE)
        override
    {}

    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
        returns (address)
    {
        return super._update(to, tokenId, auth);
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _increaseBalance(address account, uint128 value)
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
    {
        super._increaseBalance(account, value);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _checkIsTransferAllowed() private view {
		require(_isTransferAllowed, "NodeLicences: Transfer is not allowed");
	}

    function _checkValidTokenIdsForMint(uint256[] calldata tokenIdsForProof, uint256[] calldata tokenIdsForMint) private pure {
        // check if tokenId from tokenIdsForMint is present in tokenIdsForProof
        for (uint256 i; i < tokenIdsForMint.length; i++) {
            bool found = false;
            for (uint256 j; j < tokenIdsForProof.length; j++) {
                if (tokenIdsForMint[i] == tokenIdsForProof[j]) {
                    found = true;
                    break;
                }
            }
            require(found, "NodeLicences: Token id is not present in tokenIds from which the proof is generated");
        }
    }
}