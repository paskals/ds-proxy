// proxy.sol - execute actions atomically through the proxy's identity

// Copyright (C) 2017  DappHub, LLC

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

pragma solidity >=0.5.0 <0.6.0;

import "ds-auth/auth.sol";
import "ds-note/note.sol";

contract ProxyData is DSAuth, DSNote {
    ProxyAuth public proxyAuth; 
}

// Based on DSProxy
// Allows code execution using a persistant identity This can be very
// useful to execute a sequence of atomic actions. Since the owner of
// the proxy can be changed, this allows for dynamic ownership models
// i.e. a multisig
// The original proxy was modified such that it can only execute code
// only from approved contracts.
contract VaultProxy is ProxyData {

    constructor(address _authAddr) public {
        require(_authAddr != address(0), "proxy-auth-address-required");
        proxyAuth = ProxyAuth(_authAddr); 
        return true;
    }

    function() external payable {
    }

    function execute(address _target, bytes memory _data)
        public
        auth
        note
        payable
        returns (bytes memory response)
    {
        require(_target != address(0), "ds-proxy-target-address-required");
        require(proxyAuth.isAllowed(_target), "Not allowed to execute code from this address.");

        // call contract in current context
        assembly {
            let succeeded := delegatecall(sub(gas, 5000), _target, add(_data, 0x20), mload(_data), 0, 0)
            let size := returndatasize

            response := mload(0x40)
            mstore(0x40, add(response, and(add(add(size, 0x20), 0x1f), not(0x1f))))
            mstore(response, size)
            returndatacopy(add(response, 0x20), 0, size)

            switch iszero(succeeded)
            case 1 {
                // throw if delegatecall failed
                revert(add(response, 0x20), size)
            }
        }
    }

}

// Based on DSProxyFactory
// This factory deploys new proxy instances through build()
// Deployed proxy addresses are logged
contract VaultProxyFactory {
    event Created(address indexed sender, address indexed owner, address proxy, address cache);
    mapping(address=>bool) public isProxy;
    ProxyAuth public proxyAuth;

    constructor() public {
        proxyAuth = new ProxyAuth();
        proxyAuth.setOwner(msg.sender);
    }

    // deploys a new proxy instance
    // sets owner of proxy to caller
    function build() public returns (address payable proxy) {
        proxy = build(msg.sender);
    }

    // deploys a new proxy instance
    // sets custom owner of proxy
    function build(address owner) public returns (address payable proxy) {
        proxy = address(new VaultProxy(address(proxyAuth)));
        emit Created(msg.sender, owner, address(proxy), address(proxyAuth));
        VaultProxy(proxy).setOwner(owner);
        isProxy[proxy] = true;
    }
}

// based on  DSProxyCache
// This global cache stores addresses of contracts previously deployed
// by a proxy. This saves gas from repeat deployment of the same
// contracts and eliminates blockchain bloat.

// By default, all proxies deployed from the same factory store
// contracts in the same cache. The cache a proxy instance uses can be
// changed.  The cache uses the sha3 hash of a contract's bytecode to
// lookup the address
// This modified version of the cache is authenticated and it keeps a
// mapping of the addresses of all of the deployed contracts. Only officially
// deployed contracts can be executed by the proxies
contract ProxyAuth is DSAuth {
    mapping(bytes32 => address) cache;
    mapping(address => bool) public isAllowed;

    function read(bytes memory _code) public view returns (address) {
        bytes32 hash = keccak256(_code);
        return cache[hash];
    }

    function write(bytes memory _code) public auth returns (address target) {
        assembly {
            target := create(0, add(_code, 0x20), mload(_code))
            switch iszero(extcodesize(target))
            case 1 {
                // throw if contract failed to deploy
                revert(0, 0)
            }
        }
        bytes32 hash = keccak256(_code);
        cache[hash] = target;
        isAllowed[target] = true;
    }
}
