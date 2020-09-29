pragma solidity ^0.5.3;

library BN256ops {

function ecmul(uint256 ax, uint256 ay, uint256 k) internal view returns(uint256, uint256) {
 uint256[3] memory input;
 input[0] = ax;
 input[1] = ay;
 input[2] = k;
 
 uint256[2] memory p;

 assembly {
   if iszero(staticcall(gas, 0x07, input, 0x60, p, 0x40)) {
       revert(0,0)
   }
 }
 return (p[0], p[1]);
}

function ecadd(uint256 ax, uint256 ay, uint256 bx, uint256 by) internal view returns(uint256, uint256) {
 uint256[4] memory input;
 input[0] = ax;
 input[1] = ay;
 input[2] = bx;
 input[3] = by;
 
 uint256[2] memory p;

 assembly {
   if iszero(staticcall(gas, 0x06, input, 0x80, p, 0x40)) {
       revert(0,0)
   }
 }
 return (p[0], p[1]);
}

}