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
            uint256(0x2ac4806131e4e26edb06ff715d6fd8fe3eec9df48b90403874082e75d6e1b51f),
            uint256(0x0f5e7d97e0e49637a65353bec002918d34ef5409aea821babca2525b0b7fcc05)
        );
        vk.beta = Pairing.G2Point(
            [
                uint256(0x196ce7579a71d07337df675ceff079d3561724e98619c6a7a2311862d5451c88),
                uint256(0x012290f8c0f2161723261e200bbac4e8a8e2a0df8d442fcdedbe08af84fb934c)
            ],
            [
                uint256(0x182d74163bf74229fed1486c13ce05d435a092f4f46dc97de5a58ad15d5f86b6),
                uint256(0x1077319fc1e9fca4088756c0123dc3131c5b01ce4e493aa9a8a4344253ea0dca)
            ]
        );
        vk.gamma = Pairing.G2Point(
            [
                uint256(0x22b83a996ec7e6be9fffd7cc2712bbcc15752fcba78e2b3bf12c82a51f1c0e4c),
                uint256(0x11e6c20f76058a8b62a9e500679d3ae24121f8395d6c70384d8f28b4c441943f)
            ],
            [
                uint256(0x179670ed1699078d605a1c8db9591c1c599aae27e132f15c4d927fac30db9d21),
                uint256(0x12f48a9f2f81619c4dcb21847e477c7837ce9935559c6a9de96d4334da877424)
            ]
        );
        vk.delta = Pairing.G2Point(
            [
                uint256(0x27e34705208ce2dcdf84ccbec633fee7ac6ce994853c241144ad68c386534488),
                uint256(0x0076543fd456b6487bce761bcf68cd1fe74565677db128c1c894d6064cf3d452)
            ],
            [
                uint256(0x2d4655d925a6b5d517dae429e7931f1db41dd5e486f9559f746531ec3151e83d),
                uint256(0x17841aa80355d0ee8356c88dc1c71137c0666d83139916935e58cf29905d8c89)
            ]
        );
        vk.gamma_abc = new Pairing.G1Point[](131);
        vk.gamma_abc[0] = Pairing.G1Point(
            uint256(0x1b4e7bb73bd8888cca716f190f9b656a1bb7ff5bef05a28c197b6ba27ac6eec8),
            uint256(0x2c0cb6abfd829572ae6803d98a9520b56eb1f758695944eb452b82da25f39f38)
        );
        vk.gamma_abc[1] = Pairing.G1Point(
            uint256(0x2ff9c5bfa652c24a1641e9a197748c39fe359ac17429b070db3f30641e5429fd),
            uint256(0x00e4d473860da641d727e5258330364d932ca621b0aadbc53dfcadb1c0670a14)
        );
        vk.gamma_abc[2] = Pairing.G1Point(
            uint256(0x29c36b1ddf1d75a4b82b153127388555dccedf420c9c543637a69f30e8205113),
            uint256(0x18563f658e4f7ae18a05478500ef78035126fea6708515000e72eaee63a29da3)
        );
        vk.gamma_abc[3] = Pairing.G1Point(
            uint256(0x0883ea95fc10a7930af23b2090d687b66762b0967e73e441f8a8189dcb2f618b),
            uint256(0x0e71b4badcba7f928dc5830ea8607d14f65c1f5ec2c0809ff81d800d33986bf9)
        );
        vk.gamma_abc[4] = Pairing.G1Point(
            uint256(0x1f6c5672099c8dc88964ab3db8a4f8139541479da94ffe4c7cd4ec09d9d9a5de),
            uint256(0x0117999fb353e55fa95f432710938e9e90a24fe80234ed9df46ac4bbaa4ca421)
        );
        vk.gamma_abc[5] = Pairing.G1Point(
            uint256(0x084c6d698bae1712303a3f71741d0955700ad2dfcda48e599d7a6f33cac9a9e7),
            uint256(0x241f732caf76f1a686c09c4f1da6d9120218892db950f6d0e0a1bddac2af6550)
        );
        vk.gamma_abc[6] = Pairing.G1Point(
            uint256(0x0cc45c17bfc9c95f300623ee04102a5e857aa8ddb548e5ffd8252ea40c8856d6),
            uint256(0x13507dace40618c7b2f8c30fa08057cd9fb70e316effe628c17946ba18a90a63)
        );
        vk.gamma_abc[7] = Pairing.G1Point(
            uint256(0x2a8aaf727d09a79f7aa07ff50445c80b4e3157d41462c6f7515caa311524b9a1),
            uint256(0x167eb17cbe95600e308a7f680b4b073388774df9a8b52d6b25da31b65ddb3e33)
        );
        vk.gamma_abc[8] = Pairing.G1Point(
            uint256(0x03eb2028f559c400c07b0807f53043b4c05a22c21e55336d9254e9dbbde728ee),
            uint256(0x01ad42156ee805fb70e5767cecedf3a7f224164e907106a4333265d100fd5ab4)
        );
        vk.gamma_abc[9] = Pairing.G1Point(
            uint256(0x1808f79eaa66b6cfe64a156965c26a6870c5d56c30f4e7a3121ea40d3ab55649),
            uint256(0x1bb9891fa163de1e2e1c2d26934931a7019865a3e4078aaa1dfb8c389c2c8284)
        );
        vk.gamma_abc[10] = Pairing.G1Point(
            uint256(0x04175c76c00c91f77b8601d920d5a8283a6ba8d1257dd381bce1c5589df7afae),
            uint256(0x2d798e75581f1600638b997d256f0ff9ac29e6f7fd527cf1cca0b8c5bc7a5260)
        );
        vk.gamma_abc[11] = Pairing.G1Point(
            uint256(0x2da94840760301bfad1925bf054558248650feedb54ac4694c4e5e0c2e3a246d),
            uint256(0x1cda0dfd6d9f32797c32f5ad13fea3d2f0065707312b04553f16a13fbf3b3518)
        );
        vk.gamma_abc[12] = Pairing.G1Point(
            uint256(0x06c4dc0eb113ea4c4fc1ba4243209c9e04e56d5d847e8ac887a91afe0ba713c8),
            uint256(0x15a97b1146328bea592b14651d93b08db4fb444b411268874144e220bb307250)
        );
        vk.gamma_abc[13] = Pairing.G1Point(
            uint256(0x13efc03a6b7f67ba7b46389b686aab665d53b01fb4b4f77921d6fff8073dd4be),
            uint256(0x1825c6d448f266bb8d3cc0897822ad8133239e5b252b0c2df34ab07f32242938)
        );
        vk.gamma_abc[14] = Pairing.G1Point(
            uint256(0x12e468e5ce0671e01ca0d2c041904da29a129ff5cc055db8cc8320d97c082867),
            uint256(0x17a93bf08b39e1b252bedc232e5559e4f3cdf0750d123c272892246a1d40046b)
        );
        vk.gamma_abc[15] = Pairing.G1Point(
            uint256(0x2fe5d619df0ac41acfc490d759d4b12aa82180233a5f6b4f7985018024163632),
            uint256(0x2af4ef6356fe85cb6e1c0e76f8105866fcb36f3f21a91ce4d259f3da9840af85)
        );
        vk.gamma_abc[16] = Pairing.G1Point(
            uint256(0x128d78f0e361ebba215010ac6957e514ae4492acd24180c3be494b0ce44e0562),
            uint256(0x26eafef33e316f510e73010aee5a40708c0bb6ffe629db83b76d4502372ac4ce)
        );
        vk.gamma_abc[17] = Pairing.G1Point(
            uint256(0x1c9fbb229b79334624665eea40e250eca47ecac298713a48f2964f5c65fb995f),
            uint256(0x19f3ce06c2ea613e84a54c9a4d1c2163b3d9380d156d4f9437cac4fad31f311c)
        );
        vk.gamma_abc[18] = Pairing.G1Point(
            uint256(0x13f88a4b9bb09d473729a720ea0cd53f109e8301ea672a5b4b1b12dc0e3eb7c9),
            uint256(0x1a87c6868386a86f31ed83edf49fcd7aca43b970f87a9b88e553b9a58d09bb7d)
        );
        vk.gamma_abc[19] = Pairing.G1Point(
            uint256(0x16bd058e93dda977591f48d7c3783e1b4dd157b19802fc4efbd9b024a9f5366b),
            uint256(0x2576658cafb829e11fc66289c592218b66303c9cc422e0a5cd36141da3ff81be)
        );
        vk.gamma_abc[20] = Pairing.G1Point(
            uint256(0x107601e13e4a13b595366eae2472f35630b8d742ae217e2b69e6713d05f94f08),
            uint256(0x2a00a4662468a56cc411fd2315713772f5744ce0ac5f856e42f5e49dec0c89d4)
        );
        vk.gamma_abc[21] = Pairing.G1Point(
            uint256(0x0fb3319b8bae7404e0b18faf6ff954fde81786835fb58e7e32a91e48c01a6742),
            uint256(0x0281221df181ee784bf65b3379228300aac12b48b83a8d4cc3f834fe6e3de960)
        );
        vk.gamma_abc[22] = Pairing.G1Point(
            uint256(0x244100c69449516f6208ba8998f4ec9989de9d198466e446e124b82fee10f14c),
            uint256(0x1609e34c4d23ea7dc63852cecd8017b3b4f8ffa1a3d366b73c06d2ca209f3245)
        );
        vk.gamma_abc[23] = Pairing.G1Point(
            uint256(0x238f549aa115bfbacde7012b2c2efd0c2be37fc8450e43236e80ca2873d37b54),
            uint256(0x1b1dfc95bdf85eba2ad1455a3617854a6a4e6be015e949d971932f752522ceeb)
        );
        vk.gamma_abc[24] = Pairing.G1Point(
            uint256(0x1f8a5fb8b54cc65e6b57bf73dd4251b41b4994af48210809a558926bc627ee10),
            uint256(0x1c97427800290fea464dedb753d9613a34049b1674a1ae472005cca987cdf74f)
        );
        vk.gamma_abc[25] = Pairing.G1Point(
            uint256(0x1a427593c60d0c5a1a51931f4c810eede9b52807124ec396b5528ee28b067a6c),
            uint256(0x149aad4ff425d2360b235d98636e3035cc6fe2ccf1e322f0ee5a17ca9ad4322a)
        );
        vk.gamma_abc[26] = Pairing.G1Point(
            uint256(0x065a89604da44b76fdad997e1ec70c77a5ed471b41ec6dd61fdaa5e3ae1b2e6b),
            uint256(0x01074751e0cc210b9f40b0e4fdaa20fabce500e7fc8151e817992aa87b4dc628)
        );
        vk.gamma_abc[27] = Pairing.G1Point(
            uint256(0x1d467378dbe12aae41f8f55aa3c7daba3e4652c4a6d8c2b7aad920b3bac2d9e4),
            uint256(0x2252fa1f9f92b7a96e54687b0c65e0601fe3054a5d0025a6281b956f07c23372)
        );
        vk.gamma_abc[28] = Pairing.G1Point(
            uint256(0x0699113e3950b73235dfab95ac8e7dfeb41bf0055d057d1fb600a3b53a21a701),
            uint256(0x178696ae12587767dc53ebed72bfdb5af46fb0b6b3697d447ac5fb3eab2cf024)
        );
        vk.gamma_abc[29] = Pairing.G1Point(
            uint256(0x09521d58afee380278ee791104b1124de979bd63b3161e64ce71867828541644),
            uint256(0x10fa5204b820347f679794713f94c708a6a079ba16eddae716a230a4c0f3ee20)
        );
        vk.gamma_abc[30] = Pairing.G1Point(
            uint256(0x278b3a467253a8ef47e3326da1058a1ee3a6bb80df610becc499497417913c88),
            uint256(0x169805562a036298dfa2577ead3182682cbf798ab049fd6606ccb1ebbd8e147b)
        );
        vk.gamma_abc[31] = Pairing.G1Point(
            uint256(0x29da1d73c9d94135dc181f4661a2963631d9f83f19f1feb9a379c3935a922df1),
            uint256(0x0afe731f1de22a4fd84ad35d3783ebc05fd53e18aff3b39d03016c48c4e5321e)
        );
        vk.gamma_abc[32] = Pairing.G1Point(
            uint256(0x2ebc9c7b869e84e96d45282eaea697a135fdc881a20e5a5b485db37634a6240f),
            uint256(0x1c2c9e415bbe28047dc65f4af44a745c379b50700320f6b2315e6d19f4d70ebe)
        );
        vk.gamma_abc[33] = Pairing.G1Point(
            uint256(0x07c5af9bfe36f1b4c2ef71cea85788668dd3da36df99d53dea2264b7eabacc00),
            uint256(0x0668894200792864b418cd8582086c8c390db28da1ca25a4577e8b6f1b611c8c)
        );
        vk.gamma_abc[34] = Pairing.G1Point(
            uint256(0x289f9d5456a70d910ea3592b65831ceef2d1ac9fb415388fb99555a5f6a4d81b),
            uint256(0x1804389d194288198567763b7fe3db7dbf2a51a05a98ede7975e80aa6d3cd40f)
        );
        vk.gamma_abc[35] = Pairing.G1Point(
            uint256(0x279ab6cf32cedf2a29637b3d6f08500b1ac313c4450159415c28c5527bcea723),
            uint256(0x233674ceaf3149d176bdfa8dd18cbd8a39700fb3898af6929c65d9e3983bcea7)
        );
        vk.gamma_abc[36] = Pairing.G1Point(
            uint256(0x2ed16208f2de5b357b9df848667fc085d6006e0e070c44ee94e12afe8e09c520),
            uint256(0x1c15a7349ee61bc9215edc64d421a08f9fe95f6a0c9f7d7f56090d79d1084450)
        );
        vk.gamma_abc[37] = Pairing.G1Point(
            uint256(0x1887cae2aae01a36a0de9423584a7a31ec684bd46c7eed589e33ebf57f0644f0),
            uint256(0x18b5839cde198c0f1b633250eb63634981f6333781ea109c827c4bd0b95ab5bd)
        );
        vk.gamma_abc[38] = Pairing.G1Point(
            uint256(0x18e444bae726cd52bf516d4b3921d6a0465f785c6214a43296000bbd7133dcc4),
            uint256(0x0b771d6bf3e9ce1f886f8e5d679f5b69cae141d25c7e88c81171e5e8ec0ee23c)
        );
        vk.gamma_abc[39] = Pairing.G1Point(
            uint256(0x0129d5031a4f81dbed8a7444cd2b0ea21f84c861e1595d92518b1c5cce2ffa99),
            uint256(0x04c682cff58b9f08e613464b07db41ca2f648ea29ac2ab3c40f3d514a7f80cc2)
        );
        vk.gamma_abc[40] = Pairing.G1Point(
            uint256(0x00e2ca208e56cbcaf35a8a6d2d4dae7581fe3781acc3fc0d46a867cceeacf067),
            uint256(0x0c1b79b33161c6417b05b5d70be07b35f6b6510c80f798b3133926f7a8b8b934)
        );
        vk.gamma_abc[41] = Pairing.G1Point(
            uint256(0x09a2c6dc74555b0e175c2d2a773473ca051c0764f9f45611e2fe16e9a018c271),
            uint256(0x1e86662dfc02a2b2129c4051d5f30445a7637abde413d9390b79d1f6e435b368)
        );
        vk.gamma_abc[42] = Pairing.G1Point(
            uint256(0x0473472ab32187a01ee87640ddafb96ce10a53aeca5ecf1c754a6d7da1f24f7e),
            uint256(0x0fc337c53e2e3283a3be60de422cab5e04fe4a09ff6a6c2517a04667940b3738)
        );
        vk.gamma_abc[43] = Pairing.G1Point(
            uint256(0x2dee1dfe5a03c4527f93cc8aab82b8fe787cc0b8d1421c151a18d845b5aa385a),
            uint256(0x2216a933e82c9dbfe7b8f56a2d84375d69fcb309e98b37077c6e815d8f7ea1eb)
        );
        vk.gamma_abc[44] = Pairing.G1Point(
            uint256(0x2b0b6a1ccb2bb563f10b67089900eb67ff84d298e1607ab539f8b4ccd9dadc4a),
            uint256(0x156ad8794ea73994cf78af44b16122c52bfd8eed5c8e27ac1b105f20a8f9befa)
        );
        vk.gamma_abc[45] = Pairing.G1Point(
            uint256(0x04c184ddaa0754efe2ed4aad766b9d2a183ba4a33e0e3dfb1326ff18c4a6d844),
            uint256(0x08ef85de7d4a54d00b1b047f00cb0c94110fe478460e4b425b182d68a31e1f86)
        );
        vk.gamma_abc[46] = Pairing.G1Point(
            uint256(0x1d8ec80cc46b52711bae617967807a2ecbe716ccd4a1803b155583a44f8f8af0),
            uint256(0x25ca39d638d42a3eb976a967b66628258ae80f348fcc3d04dd1797f6368f384e)
        );
        vk.gamma_abc[47] = Pairing.G1Point(
            uint256(0x067bd341ba4358b0a9c565e691c121c8f86e54e85c164dc73e17536efa2a34e4),
            uint256(0x29015b4d90975f8fb287bb41ed851678771d2faf465ddb97f6b79c46f86e0f7b)
        );
        vk.gamma_abc[48] = Pairing.G1Point(
            uint256(0x24c54cd1cc43ce6ad4863f484a0f4dcf77fe04a3d9397adf9b7d933ee64c2b84),
            uint256(0x0e3ffbdb2ba62d97393fa4fc04e2b5c88ed7eb09b305d9d10de8b8573bd683b6)
        );
        vk.gamma_abc[49] = Pairing.G1Point(
            uint256(0x0b5a67242b3724c8caae827817c412f49e1edcd22ef3e8fd634830284702efe7),
            uint256(0x154cfe2fcd486cfd835fec9a29e148684f37af55d26b0f6f4dace6f4dbd8bd04)
        );
        vk.gamma_abc[50] = Pairing.G1Point(
            uint256(0x224b47ff769829137fea6cd0336125529d76595b1e5e51b299c94d3b51da54a9),
            uint256(0x26abae53ee1f8557f5f4c77a4bd430a1bb3ed88e88b098470da774ef6a76e750)
        );
        vk.gamma_abc[51] = Pairing.G1Point(
            uint256(0x034134aa497d6ef6dc469b4668c205f7aa0b8384264123ce3324322f5aeadbdb),
            uint256(0x06cb750b23e93da7159d80f5af3c379aa528cf8f6eae25124ccae80ee0f673f2)
        );
        vk.gamma_abc[52] = Pairing.G1Point(
            uint256(0x24eb0bff6372e2b0397ff46ed0c553657fe04e2368e54125a5209bb12af43c77),
            uint256(0x041bb139b27c1d5cbd8bc4051b0449d97793ce03de480383b6203d1bb6ff8d49)
        );
        vk.gamma_abc[53] = Pairing.G1Point(
            uint256(0x088b6f1a662e6c0e458ce03ee1ed3f569a1a765bf98ae9a57892033353ec9745),
            uint256(0x02a6f161b9eb96626d29639d271694b9901045710f3cc4988ffa9953904557ef)
        );
        vk.gamma_abc[54] = Pairing.G1Point(
            uint256(0x01372f40d72c0c7f39c7324f0cef8c7e4232fcd3613eb200d82a8009d2562467),
            uint256(0x002ced74d11817f49d6bc58af121f09e48447dc94420c7eca5da8f7c51639eb3)
        );
        vk.gamma_abc[55] = Pairing.G1Point(
            uint256(0x0315a3989b3bba535b083edebbb1350758a61194634ec5d26451355b137b27ea),
            uint256(0x30560b2df0d182c2bd10d951262ab1387e5c004494f6897eb9d517dd202e87c4)
        );
        vk.gamma_abc[56] = Pairing.G1Point(
            uint256(0x29b5fcab968b21fd3e2a51059e027d3ac33ae6e54f9b226c0abea8ab562dc8b2),
            uint256(0x093d7a40cf82ad7136f5fb2c4fab284e642ba66653f8c06affc9ad4adb6574f0)
        );
        vk.gamma_abc[57] = Pairing.G1Point(
            uint256(0x029d7061ab88305243b35f490777829b008e685554d67f2e3a944e77c4712629),
            uint256(0x1d5458455183206eaf77c1d83b144701e2a4a521834f96785a6c8f2e683bc49b)
        );
        vk.gamma_abc[58] = Pairing.G1Point(
            uint256(0x0563a6ce6af4e09ccf98e64c4bfb17b8e68f9475f569ac104929242029a56077),
            uint256(0x13eef757fb6c3aff65d4cbc838197a2d71ef5ffbb9cc48674c48ea9806f26484)
        );
        vk.gamma_abc[59] = Pairing.G1Point(
            uint256(0x294c54ad964ebb191d9245a099eb59c2375198d45773e6e0ad11f963451e69cd),
            uint256(0x07fb5a328af98388c8b0e3c0989b5ff3bde96055b18df2f4a81092027e6c17b4)
        );
        vk.gamma_abc[60] = Pairing.G1Point(
            uint256(0x0025d878029944700a23700431cfa04028e6cf9730136719277053fcc44f1fae),
            uint256(0x1e5f7503cb78025a3565359c98747f3c4828d5d3d8cbc3301a32c6a11faa4374)
        );
        vk.gamma_abc[61] = Pairing.G1Point(
            uint256(0x1e45ba4cbea3ecfb65b70cfb6fb2799b78c9c2e572e776a335f48e0674f917f9),
            uint256(0x0d099d400bb7a124e78da7edc7e1685ac3e5bf29d35cbafcc61e1f67beb59a34)
        );
        vk.gamma_abc[62] = Pairing.G1Point(
            uint256(0x1adcf83afafbfa0fc978ece740e4d7f4d584ebfbf11aa6bf2548ed0862f6ea51),
            uint256(0x063faa5d47fc63e01842ef27629e66f370e00dd5ed6fdc1edb6fbac71853820e)
        );
        vk.gamma_abc[63] = Pairing.G1Point(
            uint256(0x2f2704987851801cfb7d2f187747e04180255ff2030b535e1069e9a8eef39d1f),
            uint256(0x0720625c82a7f06ca2bf871989a1c03537bddd9ccb5dd98aea35d1560327a497)
        );
        vk.gamma_abc[64] = Pairing.G1Point(
            uint256(0x17ab06ddc2cdd38b8c61f70483c8a3e099b5b293ff85aec163bcd06afab17d61),
            uint256(0x10c07d720ddca2eea706d3dad8db605862ba1b2bf3dceabcfe7c5d3342233a37)
        );
        vk.gamma_abc[65] = Pairing.G1Point(
            uint256(0x064b2de5d00292bf0f1b99f486e725c6b0f6494eb5c6ee3b2e8c982958c86af3),
            uint256(0x2bb9184c857ef9a84623f51c003a7e514e291f30d6aef0e724f09edb7a005e52)
        );
        vk.gamma_abc[66] = Pairing.G1Point(
            uint256(0x118b7332caa907366fa6bd11f7d2cb6ec91d89effa94c35028c5aa1e8a02c0c1),
            uint256(0x2051e6c734cf22ddae0944a1394c93f025bdf59df25418e9a51d2f87e8fabe47)
        );
        vk.gamma_abc[67] = Pairing.G1Point(
            uint256(0x08a18df46c37982e01f8d5a4ab17cba4ce968f2e7d93867b9ac0d9b1808c55d6),
            uint256(0x0722b9e0f143c9dbe823b1c2fd738a8fe6b55bcc464ce78357e5a5ff6508a163)
        );
        vk.gamma_abc[68] = Pairing.G1Point(
            uint256(0x2223d98eb024e371b284cab889b724351ea84a0f8b5853507cde02659a88243e),
            uint256(0x0f0ac2ce172b49abc203eae0772daae1bf82610656164a8b0376573a3cfabcf9)
        );
        vk.gamma_abc[69] = Pairing.G1Point(
            uint256(0x1b606f63ed923228441e6e7aedfb781f3b29e0940d91418abeb1a1c3890bc916),
            uint256(0x129f2759a315705bb754f59e9308ead171b6975f4707677209e89c025be1ec16)
        );
        vk.gamma_abc[70] = Pairing.G1Point(
            uint256(0x1b9ea3a815d932cec3e69f5ce23f2bcf3a5586d5c76186fe0a4061b766dc099c),
            uint256(0x16ee37b888e33b80e72982ecbe910ba156cf3787b305e2e1bafa0bbdef264835)
        );
        vk.gamma_abc[71] = Pairing.G1Point(
            uint256(0x0db0a93102278f8b5e61feb7ecfd0cae677f63c5dc17f8cd5d5ef83b3278001d),
            uint256(0x083a013508c79c2a467774e1c12d2fc350e6d5a7259a6ecc0ce9bc68c3a03c29)
        );
        vk.gamma_abc[72] = Pairing.G1Point(
            uint256(0x04ed560b62baf7c2765850da9c01d1b16922e2a5a7fe9ba202cfa73f9eff6e11),
            uint256(0x0aed75ef32287c8d8e8270580021e27e9548942429e51101c1697d56802e1a6f)
        );
        vk.gamma_abc[73] = Pairing.G1Point(
            uint256(0x2678c0752c1460e8a060e6196fbe371399a5781ead8ea4212175ad20fb84a199),
            uint256(0x0e8e1d2a234599a9fbd9db046df90b33472c401f37687029f6e4679aaf1de475)
        );
        vk.gamma_abc[74] = Pairing.G1Point(
            uint256(0x2e6e0b03f38a78342bfe5450382f72b183bb1332a739b884ead14e35245e1cf6),
            uint256(0x2c9e6314998b3389f4a7d55ea5eb7bce2e63567b87ef933cb41e70d9e9537358)
        );
        vk.gamma_abc[75] = Pairing.G1Point(
            uint256(0x04199ac915a5422f845f2197733bb067a7ac12e18bfd800771c943c4d1c6dd8e),
            uint256(0x1b8365d14a93fcfa06ebcbdc5f1ec9c5f952e6ce271d29941449d3d74b883e9c)
        );
        vk.gamma_abc[76] = Pairing.G1Point(
            uint256(0x09951882a3d96f541dcf1134283321dd3b959b7a84180dac652d4e83bf1e078f),
            uint256(0x072fd0eab7d02b288eb9f315b0c44489fa9fea39a5835ad82b6ba822f40d29c8)
        );
        vk.gamma_abc[77] = Pairing.G1Point(
            uint256(0x2787813d940febed6cc9e75f40af6887e4d4fdbbec6d1e0d8f0c68a587df5a98),
            uint256(0x2c043c68d4988baea3cb7b06d231d7cd729ea75250ba864602a4424d11805f24)
        );
        vk.gamma_abc[78] = Pairing.G1Point(
            uint256(0x2e5fef7bd56d08e993389bc9d9180bbba23ca71fcd692eebdd6cf7551188ef46),
            uint256(0x1d7ec3517d31cba46f279439b56a95ca0a83649416e6b783d2cdcc5828148010)
        );
        vk.gamma_abc[79] = Pairing.G1Point(
            uint256(0x0a6fe1c84d3b7a2e89d8a4d9de8b1f2911b4cb90c7f5eb55fd3953fac630cf91),
            uint256(0x1970fc01228101a33e13eae9129ec57ae56473622d21c6ba0456fce1ce57a8f6)
        );
        vk.gamma_abc[80] = Pairing.G1Point(
            uint256(0x11c2b133e31150bd0858dfbdb78e6b76a80b312d4e137081021c856c7a4c8e53),
            uint256(0x027e775a248d181d5d073ef8d7819c243c93a88ce64729d52716e701fc993d37)
        );
        vk.gamma_abc[81] = Pairing.G1Point(
            uint256(0x208a0a8eb7f2ccfa1e95cd1fc9efb6dec3e374544b277acab11ed3fdb40e7dda),
            uint256(0x13eff77c264236e20b795204be234ddd19718ce1dd6f22777d125be7efe7f818)
        );
        vk.gamma_abc[82] = Pairing.G1Point(
            uint256(0x16f2c5ca565cc305173bd273793a12ad793e6e120a83e88588479e5b2d377b4d),
            uint256(0x2a1403261703b48661ac507c849b46421ead561600b8cc5fcff9c11ef4a1f5c6)
        );
        vk.gamma_abc[83] = Pairing.G1Point(
            uint256(0x1dbdc4641c38c7f0f35fc0f56ef96cd2440f16baebd5c705ad63b2285ce1e50c),
            uint256(0x197222eea287797d34d739c902395ac36af59cf4f9850709b183b5b762f7624d)
        );
        vk.gamma_abc[84] = Pairing.G1Point(
            uint256(0x27a98d6206e4dc0844274c6bdfdbb1c1be19b0ddc173d4acf3a075b3a0c6ecb5),
            uint256(0x13cd74d9c38a0f8e6fc4de0bf8ed6d07dac92566ea53b8e1849c4df5a64b5260)
        );
        vk.gamma_abc[85] = Pairing.G1Point(
            uint256(0x19f4647b13c76bc05d1fd6b45adc0b8530ec2d8385b3665918a174a80a1b2b7c),
            uint256(0x10ded5c2c063f212e37ef0e9fd0ef53851de57893b6ba32fbd988faaabe508c9)
        );
        vk.gamma_abc[86] = Pairing.G1Point(
            uint256(0x14e165a3a528c489b2547e055bf3199dd37251f19fa500bc0b07f897888bcaf6),
            uint256(0x091851f48f9a694cb2017ff8a3a3e92afe2e4e65cfdc1b3a835210b0998f4b99)
        );
        vk.gamma_abc[87] = Pairing.G1Point(
            uint256(0x0e96671d77dc602fed11a24d3da44501194568ece50bd35947d081be906684aa),
            uint256(0x036eaca0c4849edc95e14cbe88b498cd3fdf47452c0fb82e796ce20f762e4eab)
        );
        vk.gamma_abc[88] = Pairing.G1Point(
            uint256(0x1e96ee02b99c16a98bcbd915d05d4819530ba6262943112d70ab46cca1936b3c),
            uint256(0x26be8eaac46584419c4b146f795beb5d0426070f3405c332bbbf0d7e6684b4af)
        );
        vk.gamma_abc[89] = Pairing.G1Point(
            uint256(0x06a1f649bc927eda9782eba81d3b7cdd983c897c35ff5f033d8adf05484fb310),
            uint256(0x0ccf19e58675fa62ea134a4b4ac31d72f572bb2326a40f03b681b6ae240a0d24)
        );
        vk.gamma_abc[90] = Pairing.G1Point(
            uint256(0x069c4fd544ad37d70784e49438b3c2a08d30628b2f7ca6766dcbaf91830337b1),
            uint256(0x2f569fbd3bd5374f46688e7896a9123826c83826c7dad991da01d3c070e66c2e)
        );
        vk.gamma_abc[91] = Pairing.G1Point(
            uint256(0x05cc3822f332c70611faf723b306df8605b8580ea6b8fc84132eb061c972d7c9),
            uint256(0x1af7ae1a178b72fde37ed4ab7b255446cfa84ee0353cf9a6976afe1fd3f82c18)
        );
        vk.gamma_abc[92] = Pairing.G1Point(
            uint256(0x20b34acaf26357fe7073f5346471922c0a2b8f09a528b5ccc8a2e6b174c561b7),
            uint256(0x056db96614d8c5ede56784ef1209775e9fae256af119eb217faa7dfd792ea3d3)
        );
        vk.gamma_abc[93] = Pairing.G1Point(
            uint256(0x07d6b2520c4b8000b3dc366a5e15a371e68c368d04f8585575125d4e13829fdb),
            uint256(0x2506270fde4d89b7d0a9201ca4b2c3c47bd70e5795c3f12da33a73a487772d53)
        );
        vk.gamma_abc[94] = Pairing.G1Point(
            uint256(0x0d3a4a50166c7d2ef6a0bfc07967ad7188e9e6f1d374b6d3e27b1547ccc1b725),
            uint256(0x2e95fb292e54cf18efbc30a436fe93679f64e446c90596f2fc1c581fd8df38d3)
        );
        vk.gamma_abc[95] = Pairing.G1Point(
            uint256(0x266821e765368ab3e8c1076aafc1d34b3796cfa533c2797045a661f37effeb2a),
            uint256(0x2f1ac8ed007984de74a11bd4d88b839f50a1acf286fe8179c7f828e9b551d4d1)
        );
        vk.gamma_abc[96] = Pairing.G1Point(
            uint256(0x0a292a1896f7d36601fc4bc4e512cc8b5ccbc4d46309ee0f6c11a79b524cdb0a),
            uint256(0x281f22f3f6db8ec00021b6a34da3e4a7f275cef7297573dddb0143107b852bf3)
        );
        vk.gamma_abc[97] = Pairing.G1Point(
            uint256(0x0aa0e42568852ad2c4ffea4287ef616fccd659ed999f998f851fd6a83cbee03d),
            uint256(0x2fea1a80c80113f14b15194f34d8ffaa02aa9a6ccc297a786b3b1d1ffc8a6569)
        );
        vk.gamma_abc[98] = Pairing.G1Point(
            uint256(0x228a861ec59e6e6ef1a29759771a785553971530b31cb2601b5683a1eff84b32),
            uint256(0x06e840a722b3ed957cd1934dfd8081ef4ce0cc51545807ea397719e8b696bc20)
        );
        vk.gamma_abc[99] = Pairing.G1Point(
            uint256(0x0605e11d1295d85e64673d0619dda14740f8a05a78a7bf7328dee9bb49b0133e),
            uint256(0x20d977361ec8c7d971f118144bdf2667a1cc7b53daaac46bf058889f951984f2)
        );
        vk.gamma_abc[100] = Pairing.G1Point(
            uint256(0x2eb42a0ee98b406b720978ed1d8794e74d9d7239e1d73c133f8e04699ffd7054),
            uint256(0x1ae269e65774a6e487a04b442a01f35babbed1bc7f403e8f7ad5141697d26695)
        );
        vk.gamma_abc[101] = Pairing.G1Point(
            uint256(0x07ddbee88a60ad95d1b4a59a41d76bdc851ddb30742aa2da7b4c538494418e39),
            uint256(0x1b973d53ff91501ee6c39e2988c22338c53dd7e915729c8094027f10bba07dbc)
        );
        vk.gamma_abc[102] = Pairing.G1Point(
            uint256(0x1631d55b1191e53ecddbc18d6a25136290b8dba0a2e1008424c3fd6aa05dfb1f),
            uint256(0x238c0684cf2f44dc410127a55c9854b1a38868f39e9ec50c0ea54d344d5faa9f)
        );
        vk.gamma_abc[103] = Pairing.G1Point(
            uint256(0x24827adbb1e46b77e3e6135e846e90099702bc9fb0aab8f37b4c6f35408e2d16),
            uint256(0x0aef1aa6b321ebec41d21e63ff407f4f5da220ebfe828359f980c255af926505)
        );
        vk.gamma_abc[104] = Pairing.G1Point(
            uint256(0x0fbb34387b409538c2717b49a6634144524f3da8541e19af9a5955c2da018a67),
            uint256(0x0576dd4720383c7fb5e3914dc294c7b47724bb61fb45422731748c14c234eefd)
        );
        vk.gamma_abc[105] = Pairing.G1Point(
            uint256(0x300e6025df2c31d5ba039f11065292d6a39fda8c4f3a0ee94a0202d51068dc8f),
            uint256(0x1919a4a70e3ce28cc653e1b7fc6301e92050f2440fc687c426e21b3a41eba566)
        );
        vk.gamma_abc[106] = Pairing.G1Point(
            uint256(0x16ec00f4b76b21da2b8a1927c75bcc250f54c9d00dff74aa83640fbcec81c17c),
            uint256(0x1b27534b3575ecbc687e05369753624c2897a04aa4d3f33b29a42ef2e098bfe9)
        );
        vk.gamma_abc[107] = Pairing.G1Point(
            uint256(0x14697627b62404e6a57ec8d44132663167ee669afa74da70eb3b0b4107885d23),
            uint256(0x00754131fb9ac148e47b88dc4a0fd17415f5bd375720c8f98e94911dbd6579ab)
        );
        vk.gamma_abc[108] = Pairing.G1Point(
            uint256(0x225d37826a382529a24c0bd5ab1b2a596ba939b1506c372ee5976e7a3e3c14c2),
            uint256(0x2193bf8e409fdabd61e3d53f60546813c82c2f3d975e2f4f819ca8d40907294a)
        );
        vk.gamma_abc[109] = Pairing.G1Point(
            uint256(0x1d96eda6d6d04591d94833f241178080892a8a9963aa37ade1710cc4354f35ee),
            uint256(0x20b6ec67fc3f527d7d0be5feb2f37b5a04de7593d148b5853d7c08b715245389)
        );
        vk.gamma_abc[110] = Pairing.G1Point(
            uint256(0x0d1e0c267eedd1a9176e1040d704f4ff4ffbc74eac7a5288fde27e8ceedde3d5),
            uint256(0x0bf6d74fedf1371b6f18680c825c270dd7048701085a1d8d70c454c507132e0f)
        );
        vk.gamma_abc[111] = Pairing.G1Point(
            uint256(0x2018be8c114d3505dafc892696d4281c52e3a70835b27be8e3db9770b5f3356e),
            uint256(0x008fa3dde0f672e8332c66c673765917621007f5ebd44026f46a62a900f77337)
        );
        vk.gamma_abc[112] = Pairing.G1Point(
            uint256(0x01416401902741fa8abebfd902924a3e2bb705df8a0e244a374b3a3b72d68985),
            uint256(0x24920ba3bcf481d42c6a8455a05d85fe61c9f37dfff054111c935fe313025118)
        );
        vk.gamma_abc[113] = Pairing.G1Point(
            uint256(0x1dbee529ebf7d2487f883b02113900d33fa72d6ce680c853cb29083472786d1c),
            uint256(0x2506def46acdfc46c96ada88537b10d56c6735276cf94c8deee0ac0fb2293844)
        );
        vk.gamma_abc[114] = Pairing.G1Point(
            uint256(0x2f077ec3e1e1385133f7cfeca9878705a3b5b085db45e5ab4d876b6ce700fe5a),
            uint256(0x0427a5ae35d7e57850c531569f74fcbe88d86a509ff4fb79b8825d711d03e9c6)
        );
        vk.gamma_abc[115] = Pairing.G1Point(
            uint256(0x1c7bbe6d6fc7ecfa22985134689f92728469248dd55651848142a0795dbbc6ba),
            uint256(0x2aa727331f985f7079777de841e2700caf29528a838a2246bf0b7bb72d47b0e7)
        );
        vk.gamma_abc[116] = Pairing.G1Point(
            uint256(0x1bc7c99cfdda5eed5eacbaf081593200695c84dc5763da0f7613eb506f8605c8),
            uint256(0x2445b67615ad07579ed53186c1a08e0ea47956d436c125667365aa14e666a446)
        );
        vk.gamma_abc[117] = Pairing.G1Point(
            uint256(0x23faa6acbab9a07dfbf9304dd9e4cde0f6cf881ad4432c26a9a1675c6ae078e9),
            uint256(0x14fe56f7084b0f3b45fe9000dd7e77c9e98ce21ecdcea331c00d08a83217b810)
        );
        vk.gamma_abc[118] = Pairing.G1Point(
            uint256(0x1b3487ac41ac50e9962bbc1e19f6b0372f9ef7039e90dc35179353e25fceb92b),
            uint256(0x2cbade2a7535ae2f399ef11ea668da0cc82580b9ffd67d27160f574d3b7f6690)
        );
        vk.gamma_abc[119] = Pairing.G1Point(
            uint256(0x1b2ff7071eca181168c927011b5af0d094c5808073c2e1824d7af6f084aed71e),
            uint256(0x099071e9fc431ecb2d1776f382bf0f92e77df8eeffa582e0acd2cedf704d97a7)
        );
        vk.gamma_abc[120] = Pairing.G1Point(
            uint256(0x0ce38f342df12626e2af38ae68ecfda294c0022744d2f149fa071530f6807d01),
            uint256(0x11ee23002c5659738a702876c4a6b6558a517538e654b5e16bb8de7bcaef77e1)
        );
        vk.gamma_abc[121] = Pairing.G1Point(
            uint256(0x000784f4b7ce7a34ae983edc4c1ddc8337f9ee10ec306f79b5c497b711be4a1e),
            uint256(0x2380c0961b2fe84b15e524c8347ea58957df1b5b4101ff25efc7bda1748b4a64)
        );
        vk.gamma_abc[122] = Pairing.G1Point(
            uint256(0x25abf2941efbfd8093a19e0e3d11478b30bb0b5aff26bff5a115d363cd48c650),
            uint256(0x025d6d7cf66f6fccb3e932a8d1145c3d1158934216763cf51bd78ce26419373f)
        );
        vk.gamma_abc[123] = Pairing.G1Point(
            uint256(0x24b6b8f23c5b162c9e178ecc1e7431d96d04b924e90ad9bed5cc17978919fd67),
            uint256(0x24b003d932ec80befed753712cdc707c01f12333fd56b36f2009c6b61fca601a)
        );
        vk.gamma_abc[124] = Pairing.G1Point(
            uint256(0x09c310e54f3ac5caf1705d74648da55f5248becd37139ab73053479c9c839663),
            uint256(0x010f4b1e6d793c817f5060f201c1f4fb4475af11b61f575883499fc9d032bb8f)
        );
        vk.gamma_abc[125] = Pairing.G1Point(
            uint256(0x0ae1fdeb05b117f77671a8861b03b4efd044e21ab2f19a0dd7e74ca686df1dde),
            uint256(0x0f2f94b3d1b575fbfb686db717ab91229ff8cb122c25a3e2821ec6e9a0bd7feb)
        );
        vk.gamma_abc[126] = Pairing.G1Point(
            uint256(0x2d87cea90a07773ab4c2a127e53b8ff90488fa879144a0b014ef342a084a03b1),
            uint256(0x28ee7481dbfd5b9e072192fa7833103b25fff0c029bb4a0d91734c0b5fd029a8)
        );
        vk.gamma_abc[127] = Pairing.G1Point(
            uint256(0x170af52fba708900ff86c8f1dc1e2fbcf3722d2a6cb61626281b26a3ca822daa),
            uint256(0x0397b297fc29cbbf71472046c779db2c749033491ae7b03c9932a31658ceca23)
        );
        vk.gamma_abc[128] = Pairing.G1Point(
            uint256(0x0bf1160225a50e76bc67e93bcb12072429660d89bbaa319e59fc56de3732a481),
            uint256(0x135acc07aa64fb821c3795b84ccbd6be6a1a6f503f715fc61deb0e05e46bd20f)
        );
        vk.gamma_abc[129] = Pairing.G1Point(
            uint256(0x1cfd3d344e64f84b0a7203561dd72c45af81092abbbf1a4bdc14663894c4c09e),
            uint256(0x067155958bce0e3347dcc87da06e03a43e624af71b6416ed6ff2a1f31f915209)
        );
        vk.gamma_abc[130] = Pairing.G1Point(
            uint256(0x2bec0cadb67951f75bd85f4b71626d5675ce2b44c31af0b45acd1b6814ca2b1e),
            uint256(0x15010edb4de246d9dd72d26538a2a7d0914be85fe8eb1208892ea18318a5d7a7)
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

    function verifyTx(Proof memory proof, uint256[130] memory input) public view returns (bool r) {
        uint256[] memory inputValues = new uint256[](130);

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
