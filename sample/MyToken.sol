pragma solidity ^0.7.0;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/token/ERC20/IERC20.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v3.4.0/contracts/math/SafeMath.sol";

contract VulnerableToken is IERC20 {
  using SafeMath for uint256;

  string public name;
  string public symbol;
  uint8 public decimals;
  uint256 public totalSupply;

  mapping(address => uint256) private _balances;
  mapping(address => mapping(address => uint256)) private _allowances;

  // Vulnerability: Unhashed password variable marked as private
  bytes32 private passwordHash;

  // Vulnerability: Authorization through tx.origin
  address public owner;

  constructor(
    string memory _name,
    string memory _symbol,
    uint8 _decimals,
    uint256 _totalSupply,
    bytes32 _password
  ) {
    name = _name;
    symbol = _symbol;
    decimals = _decimals;
    totalSupply = _totalSupply;
    _balances[msg.sender] = _totalSupply;
    passwordHash = _password;
    owner = tx.origin;
  }

  function balanceOf(address account) external view override returns (uint256) {
    return _balances[account];
  }

  function transfer(
    address recipient,
    uint256 amount
  ) external override returns (bool) {
    _transfer(msg.sender, recipient, amount);
    return true;
  }

  function allowance(
    address owner,
    address spender
  ) external view override returns (uint256) {
    return _allowances[owner][spender];
  }

  function approve(
    address spender,
    uint256 amount
  ) external override returns (bool) {
    _approve(msg.sender, spender, amount);
    return true;
  }

  function transferFrom(
    address sender,
    address recipient,
    uint256 amount
  ) external override returns (bool) {
    _transfer(sender, recipient, amount);
    _approve(sender, msg.sender, _allowances[sender][msg.sender].sub(amount));
    return true;
  }

  // Vulnerability: Reentrancy attack
  function withdraw(uint256 amount) external {
    require(_balances[msg.sender] >= amount, "Insufficient balance");
    (bool success, ) = msg.sender.call{ value: amount }("");
    require(success, "Transfer failed");
    _balances[msg.sender] = _balances[msg.sender].sub(amount);
  }

  function _transfer(
    address sender,
    address recipient,
    uint256 amount
  ) internal {
    require(sender != address(0), "ERC20: transfer from the zero address");
    require(recipient != address(0), "ERC20: transfer to the zero address");
    require(
      _balances[sender] >= amount,
      "ERC20: transfer amount exceeds balance"
    );

    _balances[sender] = _balances[sender].sub(amount);
    _balances[recipient] = _balances[recipient].add(amount);
    emit Transfer(sender, recipient, amount);
  }

  function _approve(address owner, address spender, uint256 amount) internal {
    require(owner != address(0), "ERC20: approve from the zero address");
    require(spender != address(0), "ERC20: approve to the zero address");

    _allowances[owner][spender] = amount;
    emit Approval(owner, spender, amount);
  }

  // Vulnerability: Unhashed password variable marked as private
  function getPasswordHash() external view returns (bytes32) {
    require(msg.sender == owner, "Unauthorized access");
    return passwordHash;
  }

  // Vulnerability: Authorization through tx.origin
  function changeOwner(address newOwner, string memory newPassword) external {
    require(tx.origin == owner, "Unauthorized access");
    require(newOwner != address(0), "New owner cannot be the zero address");
    owner = newOwner;
    passwordHash = keccak256(abi.encodePacked(newPassword));
  }
}
