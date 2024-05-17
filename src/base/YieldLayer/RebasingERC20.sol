// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

import {FixedPointMathLib} from "@solmate/utils/FixedPointMathLib.sol";

abstract contract RebasingERC20 {
    using FixedPointMathLib for uint256;
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Transfer(address indexed from, address indexed to, uint256 amount);

    event Approval(address indexed owner, address indexed spender, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            METADATA STORAGE
    //////////////////////////////////////////////////////////////*/

    string public name;

    string public symbol;

    uint8 public immutable decimals;

    /*//////////////////////////////////////////////////////////////
                              ERC20 STORAGE
    //////////////////////////////////////////////////////////////*/

    uint256 internal _totalSupply;

    mapping(address => uint256) internal _balance;

    mapping(address => mapping(address => uint256)) internal _allowance;

    /*//////////////////////////////////////////////////////////////
                            EIP-2612 STORAGE
    //////////////////////////////////////////////////////////////*/

    uint256 internal immutable INITIAL_CHAIN_ID;

    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    mapping(address => uint256) public nonces;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(string memory _name, string memory _symbol, uint8 _decimals) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;

        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();
    }

    /*//////////////////////////////////////////////////////////////
                               REBASING LOGIC
    //////////////////////////////////////////////////////////////*/

    function _getRate() internal view virtual returns (uint256);

    /*//////////////////////////////////////////////////////////////
                               ERC20 LOGIC
    //////////////////////////////////////////////////////////////*/

    function approve(address spender, uint256 amount) public virtual returns (bool) {
        uint256 amountRateAdjusted = amount.mulDivDown(10 ** decimals, _getRate());

        _allowance[msg.sender][spender] = amountRateAdjusted;

        emit Approval(msg.sender, spender, amount);

        return true;
    }

    function transfer(address to, uint256 amount) public virtual returns (bool) {
        uint256 amountRateAdjusted = amount.mulDivDown(10 ** decimals, _getRate());

        _balance[msg.sender] -= amountRateAdjusted;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            _balance[to] += amountRateAdjusted;
        }

        emit Transfer(msg.sender, to, amountRateAdjusted);

        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public virtual returns (bool) {
        uint256 allowed = _allowance[from][msg.sender]; // Saves gas for limited approvals.

        uint256 amountRateAdjusted = amount.mulDivDown(10 ** decimals, _getRate());

        if (allowed != type(uint256).max) _allowance[from][msg.sender] = allowed - amountRateAdjusted;

        _balance[from] -= amountRateAdjusted;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            _balance[to] += amountRateAdjusted;
        }

        emit Transfer(from, to, amount);

        return true;
    }

    function balanceOf(address account) public view virtual returns (uint256) {
        return _balance[account].mulDivDown(_getRate(), 10 ** decimals);
    }

    function allowance(address owner, address spender) public view virtual returns (uint256) {
        return _allowance[owner][spender].mulDivDown(_getRate(), 10 ** decimals);
    }

    function totalSupply() public view virtual returns (uint256) {
        return _totalSupply.mulDivDown(_getRate(), 10 ** decimals);
    }

    /*//////////////////////////////////////////////////////////////
                             EIP-2612 LOGIC
    //////////////////////////////////////////////////////////////*/

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        public
        virtual
    {
        require(deadline >= block.timestamp, "PERMIT_DEADLINE_EXPIRED");

        // Unchecked because the only math done is incrementing
        // the owner's nonce which cannot realistically overflow.
        unchecked {
            address recoveredAddress = ecrecover(
                keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        DOMAIN_SEPARATOR(),
                        keccak256(
                            abi.encode(
                                keccak256(
                                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                                ),
                                owner,
                                spender,
                                value,
                                nonces[owner]++,
                                deadline
                            )
                        )
                    )
                ),
                v,
                r,
                s
            );

            require(recoveredAddress != address(0) && recoveredAddress == owner, "INVALID_SIGNER");

            uint256 valueRateAdjusted = value.mulDivDown(10 ** decimals, _getRate());

            _allowance[recoveredAddress][spender] = valueRateAdjusted;
        }

        emit Approval(owner, spender, value);
    }

    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : computeDomainSeparator();
    }

    function computeDomainSeparator() internal view virtual returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL MINT/BURN LOGIC
    //////////////////////////////////////////////////////////////*/

    function _mint(address to, uint256 amountRateAdjusted) internal virtual {
        _totalSupply += amountRateAdjusted;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            _balance[to] += amountRateAdjusted;
        }

        emit Transfer(address(0), to, amountRateAdjusted);
    }

    function _burn(address from, uint256 amountRateAdjusted) internal virtual {
        _balance[from] -= amountRateAdjusted;

        // Cannot underflow because a user's balance
        // will never be larger than the total supply.
        unchecked {
            _totalSupply -= amountRateAdjusted;
        }

        emit Transfer(from, address(0), amountRateAdjusted);
    }
}
