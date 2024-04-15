// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

library Pairing {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]

    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }
    /// @return the generator of G1

    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2

    function P2() internal pure returns (G2Point memory) {
        return G2Point(
            [
                10857046999023057135944570762232829481370756359578518086990519993285655852781,
                11559732032986387107991004021392285783925812861821192530917403151452391805634
            ],
            [
                8495653923123431417604973247489272438418190587263600148770280649306958101930,
                4082367875863433681332203403145435568316851327593401208105741076214120093531
            ]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        }
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1

    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success);
    }

    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.

    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.

    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2)
        internal
        view
        returns (bool)
    {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.

    function pairingProd3(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.

    function pairingProd4(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;

    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }

    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(
            uint256(0x07aa7d8b398846372563cbf737ef4f1a58e63be81cbd18eae4fad66802efe12a),
            uint256(0x22bf647209b6fe8627bf2f445976c0b5cd4c92a1a4d347bc75ac5d3441596a24)
        );
        vk.beta = Pairing.G2Point(
            [
                uint256(0x018dae0f5ac172cf912c1754167e5cef7784a054855d9e8d157cb5df02952db2),
                uint256(0x284ae3724deef13e93cd0ebe262680d0fed3ae78070fbc62bb6820d14f6973ff)
            ],
            [
                uint256(0x0eadedf499a7a1a5f06339e8674b85bd71e8b986fd2d832f2b4f683c6f8ea26d),
                uint256(0x305a6642f11e842745d12627ac50e5465331bc3d9fc6fb6574014235b2e7de3f)
            ]
        );
        vk.gamma = Pairing.G2Point(
            [
                uint256(0x1d9bede11ebd0748c405687fa87f9f5c44bc17580b53cb7adf0746df27120595),
                uint256(0x09776c0e0089df530b55a44b988a6de58624914b8af6d8faeefef96716f5a197)
            ],
            [
                uint256(0x04076b9127c934cdca5430370f1dd96cbfb705304aeb6568f8fa4dcadc92690f),
                uint256(0x16a44e6a83ef9c1a80f425f29ab69f251e9f0b5d00c8df9099104803928bcf62)
            ]
        );
        vk.delta = Pairing.G2Point(
            [
                uint256(0x2b39d536361e9aceb7ca8037f909db75322cc7cbf5dbc7af0c94cd79f525926d),
                uint256(0x3039da93a67647aae2c0e5d21abb866de8c8461995e91874aa5c8b3d1fdb6500)
            ],
            [
                uint256(0x047e78793f55b23cd7b799bf100641092b139a3e47465bc49f136bb06600adcd),
                uint256(0x0a99767cbb3ee1d5af11d93aa584c2b970e8dd1044fc815f03143a2fcdc2e59f)
            ]
        );
        vk.gamma_abc = new Pairing.G1Point[](7);
        vk.gamma_abc[0] = Pairing.G1Point(
            uint256(0x26a824d4a92c24b3653054c9621b7ae5ef71d39f78848335df94a7a26a292e53),
            uint256(0x17e3c3a104f4245b71da859fd786ba9dee49df4b4d547e0df3be715209ab900b)
        );
        vk.gamma_abc[1] = Pairing.G1Point(
            uint256(0x2c98da93ab3342a88c6c49c8fa5af87297ac8d28cfbdfb3c15220965e2408c75),
            uint256(0x1e5bc8abda58556e3775e3240cc57de1b7b3b5c44d97fdec8f8edc935979522d)
        );
        vk.gamma_abc[2] = Pairing.G1Point(
            uint256(0x0de5a5399b75b8f3becd1c319995ab15978932d2732584734fb9238924a30db7),
            uint256(0x2f530b40fc318ff8b085ba0607cd3d269078cd4e610b54b7831d6f202e18bc5d)
        );
        vk.gamma_abc[3] = Pairing.G1Point(
            uint256(0x286a1df18b07699b0411f96a527f2cfbcfa6538c1573219f33eb005b5c7c013e),
            uint256(0x0510396da6635d67af546de5f4f3e4888752b0d0b97700f13c2a32613d97a894)
        );
        vk.gamma_abc[4] = Pairing.G1Point(
            uint256(0x196c33782d34f61372857d4660af5783d4bcba5ab2f309feaf8ae835ff251ce0),
            uint256(0x01d8e1ad29aff793e139c115aec10b52982290a4c4266ff9c3a6460f12858ccf)
        );
        vk.gamma_abc[5] = Pairing.G1Point(
            uint256(0x102bfd19a92d274015fbadff9b25bfe897d521760b492eeb8b5246b548193798),
            uint256(0x1b3a2d553be4a77ec47a5d6ca579d0a6dadbd58f2bcc9ca7decfa043d860522e)
        );
        vk.gamma_abc[6] = Pairing.G1Point(
            uint256(0x0de1decb02bfe4eb2aff48d62a70ed721e5886acc75a56c84241aab9cfa9806e),
            uint256(0x0c56fe8bfa482b2dbca0297e59b4a123d9572d08bb4ae9f21fa74d61df3abd94)
        );
    }

    function verify(uint256[] memory input, Proof memory proof) internal view returns (uint256) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint256 i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if (
            !Pairing.pairingProd4(
                proof.a,
                proof.b,
                Pairing.negate(vk_x),
                vk.gamma,
                Pairing.negate(proof.c),
                vk.delta,
                Pairing.negate(vk.alpha),
                vk.beta
            )
        ) return 1;
        return 0;
    }

    function verifyTx(Proof memory proof, uint256[6] memory input) public view returns (bool r) {
        uint256[] memory inputValues = new uint256[](6);

        for (uint256 i = 0; i < input.length; i++) {
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
