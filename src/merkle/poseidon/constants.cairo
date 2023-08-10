use traits::Into;
use option::OptionTrait;
use array::ArrayTrait;

use renegade_contracts::verifier::scalar::Scalar;


/// Number of full S-box rounds
const FULL_ROUNDS: usize = 4;
/// Number of partial S-box rounds
const PARTIAL_ROUNDS: usize = 56;
/// Alpha (exponent for S-box)
const ALPHA: u256 = 5;
/// Rate
const RATE: usize = 2;
/// Capacity
const CAPACITY: usize = 1;

// --------------
// | MDS MATRIX |
// --------------

fn mds() -> Array<Array<Scalar>> {
    let mut mds_0 = ArrayTrait::new();
    let mut mds_1 = ArrayTrait::new();
    let mut mds_2 = ArrayTrait::new();

    mds_0.append(0x15c142510ad5a75d700b3d6f2c0ed1438dd2158f725ac45b81ed9025c370dc3.into());
    mds_0.append(0x6bcaca027ccf862050ac180b580dac05c343f889525a8d137ecb86fb64acee2.into());
    mds_0.append(0x140b07821d9ccb9a351e99a4a8ec0c87cfba2fc1c6e3101ff855465d70fb318.into());

    mds_1.append(0x7a95126f2a4415332f301d28b98f5f321b0bd8d47ebbe3331c1ed5173075895.into());
    mds_1.append(0x09ebaca9adce7aec4acb0dc1f851bb31662b8e109b4379607cd2cc493c55939.into());
    mds_1.append(0x61536cf5606c6c8585c319325f345442282b96a02c5508f2741120f0c43146d.into());

    mds_2.append(0x50a3832fbb731e86c565118a22471afc9cddb7ee66fd477af2d8386a5c32504.into());
    mds_2.append(0x3374ef85b1414c3da21ca805db66494c9966c64fa4e0ca2a93f653aabf21378.into());
    mds_2.append(0x674f9fd4494bc49836a58ea48bfa7196c882360cc0fde437c310303f83d7939.into());

    let mut mds = ArrayTrait::new();
    mds.append(mds_0);
    mds.append(mds_1);
    mds.append(mds_2);

    mds
}


// DUMMY VALUES
// TODO: Hardcode all round constants
fn round_constants() -> Array<Array<Scalar>> {
    let mut round_constants = ArrayTrait::new();

    let mut all_constants: Array<Scalar> = ArrayTrait::new();

    all_constants.append(0x27eed94d7f6f47c254d29fce05d73cf4358b38d6c01240710680538628bb758.into());
    all_constants.append(0x28d3a4161b9a54e9134181f535a2acec7918ee8691eb681e50a6b2b6194af06.into());
    all_constants.append(0x2a2fffcc5e547e1638b14a57727ec32f31a1e56d17676be648591d19305dda1.into());
    all_constants.append(0x68dc80f7274a0582feb0be68e7edeb121e3c0403356a150555fd6981a6ad531.into());
    all_constants.append(0x4471dfda42bea8d06d8a3d7c61c6bf96336935ba09fac616bcbf1db090277bc.into());
    all_constants.append(0x68dcee3dc200e286fccbf1adedc0f046c883782b6d35f63666df3c40dff49b1.into());
    all_constants.append(0x6dcd41be11ef10d10c22cdc2e0ec848b76b75db2c2d2dcc49032decde25200c.into());
    all_constants.append(0x7cfdd23464808c4a58a9357925e64bb942bd38e4e8120cf38a17d764fbd0fd6.into());
    all_constants.append(0x70e8d3c9011d9bda03979f25feaae3f119eba608d3d5260b5aa3fdb20a265e7.into());
    all_constants.append(0x7acab9fde303b83806f96d431328b1936f13bb279aa1f1e0da934b927737576.into());
    all_constants.append(0x0169392b57b0b39a0e76043b0b27967e287935b1fefdfe24d051204432a028b.into());
    all_constants.append(0x13371e93654416fa55819f40b824422f06747dab4549e6ebc617d35014ddda0.into());
    all_constants.append(0x617f158242af445821fe36e069268eab0feb7ab7a6a9c64cb90d661756d2ff5.into());
    all_constants.append(0x159bf308a6aa5cba675265162f184cd2363e23d0061cb2d0a43b35a4abbdb58.into());
    all_constants.append(0x62f01e3af097215ae033484a5c1745f28286f375aa1d129dcfe71762fe85ef4.into());
    all_constants.append(0x7064925702f2a468cb67745599992ed477b123cde5b384093aff1b93e513c58.into());
    all_constants.append(0x09a9a9f2afbd1740fa9ff4c504eaaa3170760fc5c1d855b05e7c200ab52d623.into());
    all_constants.append(0x5321cc718aa18a730080dbb74c900f0fef0c6c2dfa227541fc9f0c2ef059b49.into());
    all_constants.append(0x726b127e6cc537413329c2638e282971dce56ee1eba89044cc810b2e9c75295.into());
    all_constants.append(0x04da413ab0e5156adb5913823a39013422dcb2c0759c424d8b23b8751105d27.into());
    all_constants.append(0x7b348b0d3afe5c6d9434c2827663a3d634648efeee7bf2e63b2907b45ea1c4a.into());
    all_constants.append(0x09e327c305512399520fee363a3154478651bac29ccc5635b2f5a9a150a89a5.into());
    all_constants.append(0x723ee11556f4736be1cc7665acbec25434398b3f0cf01e5235f838ddbd2a184.into());
    all_constants.append(0x3b4f73a3f3a068ec01e0fafac01179a1dfa7f02328b9ffae3443c0331d68013.into());
    all_constants.append(0x6d60123303ae2b6b353df1d1b9b625e8241d2067895befb23fdd14628945324.into());
    all_constants.append(0x4f8b9302e1d1a74365031a50213ed0a61deabbb720c6ae3639b3b10df2a8e9b.into());
    all_constants.append(0x2de08fd886a67f78cced64ae53c473eb21f81ab8deedc94028e5c14c7f527a8.into());
    all_constants.append(0x610c1b7e39442f4fee9447fc98cb2ba534c5f311a0d627ed0aaf1abf412652f.into());
    all_constants.append(0x5298284f5cd468a359a4ebc9d23f3ea4cb82956e61e2ec25ad769cd882eb60a.into());
    all_constants.append(0x475c51c5f14d2360083b6e99fb636ca3983b7267e996758e3e86c2e4f53c8d3.into());
    all_constants.append(0x62aa51047838ea30e71b2d00a2604b1b5958bc95010d4e7a656ff8591f35574.into());
    all_constants.append(0x25c74aed69491c6062f39f524e261ea6d613bccd9ed4c926657bbc2517b0121.into());
    all_constants.append(0x10e2d7d4287c0bdb77dd75334ad1fd773849d01c94fb56d466409278253ce18.into());
    all_constants.append(0x693ada333542141ddeaf050e0345a6ff2bda61dc8b522065c624b848a13d478.into());
    all_constants.append(0x5a285a6b50af09655ec7f68fd00d8a48dac1e25a83865144af05f5cd14877f1.into());
    all_constants.append(0x41acea4db63a90c39eb9bcd5e2d217b5d544f4e522d59dfb70b264b6962ce0d.into());
    all_constants.append(0x21f55689f190d7c8cffc6d5cc7b3fa7b3d14c96d8d65eb1fce6224e283234d9.into());
    all_constants.append(0x74bcd2763f5e667b96358f4f586ea6aff9a5834b72a4c41d5687cf3fa4cd5cb.into());
    all_constants.append(0x7eafde9d2a7b8519b07c5c12d86dcf26a6d02cd72ca594e3882f5d8a54a372e.into());
    all_constants.append(0x397920b87151f76b4d2748724234680c4af0c0b227a1b902db03eba95ae4106.into());
    all_constants.append(0x0a003b0aae34712f6e340a32fdb28cc23eb3ba146754c50ea6d5164f7b86304.into());
    all_constants.append(0x4c6af438f2035f595b7519c6878b4f647f664a783b28dc1d8dd0fdbc094f33e.into());
    all_constants.append(0x393741e2ea4576b77f71f4a2753ccca152e69f417e301dafbdf3c2d921c9539.into());
    all_constants.append(0x6d691cc27352425a6d7d4f8145fc9e3b4de600d080922976d00352747e7549d.into());
    all_constants.append(0x28af384bd0db46b66b43b83008a2324d3c4a4f00b3161ee70f8a57b84ea8f41.into());
    all_constants.append(0x139e6d23bc0a868b9ad2c85e5303faf10cf53f8b006283f1caf7fc3c5972f97.into());
    all_constants.append(0x4548f399e63675e13bfd344b12336a7e3de2a352b36578876e4461bb829e9ad.into());
    all_constants.append(0x64b6dbf861967439f56b2bce22edb4d4e8c90757a29b3d7fa02b86a4ccdbbce.into());
    all_constants.append(0x5210af22881a089f1a281059693dd84035add8e11f906d7af5411ab0cdaaaa3.into());
    all_constants.append(0x01df81efd8890db4d3aa096d1c4795c1bf9f760a3bda7e1cc8373a2e0e317be.into());
    all_constants.append(0x6b7d5971e48e4a33d841b007c60e53d08a445561bfbf0ff90668220b1be8644.into());
    all_constants.append(0x41174878acd1b084e7aa8d08909779eeaa5dee4ee7ae10e3b474d9ed2288fee.into());
    all_constants.append(0x0601f43a2a69ae5dba2954493c721a90261f262c13b919dd7aaf4c0e950c247.into());
    all_constants.append(0x522bb760662a298dbd3020e32b142f9f697408ac41aa62d309f638797fbed90.into());
    all_constants.append(0x1567a51295873a63954d47aad4931390da2c469fff06a1d0216bdb490c2109a.into());
    all_constants.append(0x1924dac318de31dc500f150a1af687fc8a906a801f2ecc2ccfb53127551d9c6.into());
    all_constants.append(0x5424b3bf6ae0f01f1e9f7f780302d1621e5f930d5d56fc648c6e8958f6e5884.into());
    all_constants.append(0x0e654dd84ac1c8ff42de4846a6fc35f144767730053b63c08595201f3461efc.into());
    all_constants.append(0x64ecf7f6189ae33b609cb3a8bdb15c1282cc20b0c4e17e29dfdb6d249a7c3eb.into());
    all_constants.append(0x016250e7976898f05257813356a213a91eee15a4dfe45cde11ecbf6eb98ac42.into());
    all_constants.append(0x7e72a20ff2e0e9ac5fd567055606032a6725a7b1f9fa03d88f9c272a8e76b0a.into());
    all_constants.append(0x143e221206777a4dd9a3fd3a9c3af84e2143f5f93090a1be4f202d7cb092835.into());
    all_constants.append(0x031d610f46a7cd3ffc8ac2a306c13b230d8c7ba66eddc3f4e8a2cb64683faeb.into());
    all_constants.append(0x42c11e83fc06f194e455a0029b15061e0f71a70cf783e7c4e588fe049580083.into());
    all_constants.append(0x776ae7fa6c3f375cf2e71ac14c175767d5379a42fa23ca1786dab6592e54805.into());
    all_constants.append(0x287d9c271337fd512031249374a4e495f42e238e9b5eaeffc8e3f2605793be2.into());
    all_constants.append(0x4f4111a12be7a0ce17920e930b74f93afcd130604dd35ff650dd18cd499a3cd.into());
    all_constants.append(0x3b67bcaab624645c56d092bb2666ad98d043b2bd46cb1e574552817bc19eefe.into());
    all_constants.append(0x31cb61bf19509566bc157725523ad8da7f552243c8ad00f099170d0aa3a626c.into());
    all_constants.append(0x5f770379c678f84edd0f951159a5537dd4c412a0f27269c9ad24bd76fc31f70.into());
    all_constants.append(0x663af090a0ee43a8ca049959e658d5c2a1513ce67966840367a7d8805e0f141.into());
    all_constants.append(0x258ff602d6d41def53eb9847ab9065f0089eed9ebc27848bc9eca4f27102451.into());
    all_constants.append(0x403c8d83f36d8c10a50c1b4c3f428f3cee18b70b8887c1410efee6a4188332f.into());
    all_constants.append(0x48c0129c7a735617804327e769964439bd8f15c65bce9a6677e7cd50174d4a0.into());
    all_constants.append(0x1756a6b6ee8869e883807a1dd6a9bc46d3df55f427fca9f42d4b744f0769ad4.into());
    all_constants.append(0x5f2210d44efadbd4defcd1799ffb3c10e7d14328dbe07d5871cf23e96d7d557.into());
    all_constants.append(0x51dfec1ca571d69b96300216aec14086e54798b4acfc170b1b6dc7cc7cd7f68.into());
    all_constants.append(0x146277c3ea293a13977ecaa7fd604699ac0929f515e99106f6b420544a724a9.into());
    all_constants.append(0x14e8beb09dc4b4c6724dcd1f1803977cf4493a0e6242aca78d1bd1322b441f0.into());
    all_constants.append(0x4e9d0977b227d8e5c943eb0195213775b926619d3a1fe4f8c39b8428e5f704a.into());
    all_constants.append(0x451a8235f05f5909ebbf94bac3b3bc1d9c0130841d5413e24c6c690a17ad557.into());
    all_constants.append(0x76892b48ee0d18ae2407e30a7b8c963fd8449116463c7019ee686c61f04c083.into());
    all_constants.append(0x1af763c8f3cfaa3edc49205e0081be59a41438f0492b2ed519dfa4664f6f6ab.into());
    all_constants.append(0x56c60fecb812f16abcfd72d1c10d78b1d023c77f525de871c5641f504ab8131.into());
    all_constants.append(0x30cc7688ec7b4e8b9c9792db5f433d29a46a5302630a86945653e008c20b9f5.into());
    all_constants.append(0x4199755b34f7758e7a1029ba1090b8742b9fb9263805fbccc3fb5f9130fedbd.into());
    all_constants.append(0x2484d06b2270cbedf7b9ca19f32ca792148c647faaf5c5e96fc29a6cd3885ce.into());
    all_constants.append(0x2e427f22b17a763503edc3de0a51c72d0a3817032fa96edc4ed0839f1383dfe.into());
    all_constants.append(0x5aefb65a230cb9adfda29ca7967909fc9f99abb9a028ffa2af8193db8c4cc18.into());
    all_constants.append(0x12202f2312070a9f1bbce26672fb483ca57c6dd48b48abb6bf7aa7261e56b80.into());
    all_constants.append(0x3f7f9fd42d66b2f0874efdb148ec72d392b671dcb16dd3014f8773a531258da.into());
    all_constants.append(0x1332c2e57955b010272e3ea72aeaec80d7bff5c2662d9786b898d9eb340679e.into());
    all_constants.append(0x3c20716b1ea1d0a507f4332deea9fa45af81af0ffe6b44fd758c6b3e9ac85f4.into());
    all_constants.append(0x74a5c110aa84e2b05f6b2113ada6f29b58389750d04803db7d7c3c2e675d851.into());
    all_constants.append(0x649b9510e051938c7889fe1e57f9aa1a0eb63aee98ca1f00c0209adb461d8f5.into());
    all_constants.append(0x7d51424eb1d4cfd343f4f586bdd6c01699f3daa254b8cce7bc2f757f9c8c476.into());
    all_constants.append(0x1c6ca80d91d4dbcc1518bcbbad8046008f648a4b4bc8f2a760fb9ad74055b9a.into());
    all_constants.append(0x2b8940e70d4a634c49df6bda92ab49b4d03a598234b4742fa9037d226303f60.into());
    all_constants.append(0x5cd04ba403a25e680e363f85ab5c5d16b4305a42b8b9fac346a36893f733a66.into());
    all_constants.append(0x2f49367ed89bd1b02080dc75d5e4e27745688206d92d2cc24118c86d1e54e86.into());
    all_constants.append(0x7f489778872d89f8fefbc9cf4677e34508330311ff667564875962fec10f4c7.into());
    all_constants.append(0x058f8111ea5afa2cc8eddf77864cac5a953f9d91b1f1a919d61f57640a8e479.into());
    all_constants.append(0x5fd4635695489f5884b3c3ea3f2390fef3cfd09413cba53c1072fd5221fccf6.into());
    all_constants.append(0x6a1422455ec6e652e2e4b7d006e471bef6ce45d4f9a2104fae98524eab934a5.into());
    all_constants.append(0x3c286e7d3d0068986a150823eb8cc5ca034fa9bbb54d771eb4f761830514209.into());
    all_constants.append(0x5c4a198f7ae0074abdf903d4880733769a6a5825e015f006ee94ada1710e1b5.into());
    all_constants.append(0x02255aaf9a8a60e07338f2ee60ecd43ab918be8804b57d5a7287cb938c59374.into());
    all_constants.append(0x0c0cb45a5968435a61b3966c0b0cb724f9d37dd1fe6834361471d98d2186b4e.into());
    all_constants.append(0x54e6ebed0d097fbe88fca9d04a1ca1e9b0ebcacf91402e4dfddac5f5f4f9bf3.into());
    all_constants.append(0x68f080736a624ce492b796ad4501d6dfcd9257f818bdda60a3a5a31895f0987.into());
    all_constants.append(0x1654443a3b2d459808bcdaddce60da906d6c0354db813a94b2d7c8a1b4654fb.into());
    all_constants.append(0x4bf3d3640c91bbe29b3d550886580fb37013c8d55718655961e23cbb684b3d6.into());
    all_constants.append(0x56b611db5cf8453c23772dddca76ef498ffe0a6af666ca83e7bcd1b10a984b2.into());
    all_constants.append(0x7a34d8a175953a51c454ff60b67deb2b54893b839df14b2f93776fd4e209b21.into());
    all_constants.append(0x5a3d4ae5d48508e5ffea3f8ad19cba13b9d9e49917d3ca9c3abeaf5984f1d7e.into());
    all_constants.append(0x18e56c11e145c3c5ee168eab0efef75dd6a7708f2374a8a933871783d4304d5.into());
    all_constants.append(0x69b709188e63762ef2506f66cb82aecd3bc908d93283356b74136f1ad89b58b.into());
    all_constants.append(0x4b7fed0dabf8177f7d8f24d15548288d1a7a8df63ecb0b4850b0a53816b8d76.into());
    all_constants.append(0x4a12316fa575b562eb8aa1ab0dd21f69379b0ad754e394e4c265649aeb66c75.into());
    all_constants.append(0x4695b1ffcff7d527b51e96d784fa0c54459f4f38fb62275a3a0af74451ab3a5.into());
    all_constants.append(0x480266ceb9444ece3e34b926359868cd363516c1b829de8d020b3ff3cb9c8eb.into());
    all_constants.append(0x5666c475ef9d199594e2fdfeaabfc31de30355e72e6fe1ecadddd7ab756999c.into());
    all_constants.append(0x46aeb2ba2092a003dd64982cf24c7d675350c3f3e74e6bad242474e8dc69867.into());
    all_constants.append(0x373e0061654664472a5898aa8a80f89dd90a72e2a8718c4b85bad801b9ca2f6.into());
    all_constants.append(0x77d0a05b2d97c0d7e03dc613f3ee9ad54303b143e822e1500b78d6f18fa52f4.into());
    all_constants.append(0x47a3810a9620cefecd5cc076811e70667e406fd049b788b24352d789311d8bb.into());
    all_constants.append(0x0d1a0de91e079e0832d254194318644ad9c73024c4791251a980ffbf3cc8b58.into());
    all_constants.append(0x06d763021c81a448f41ddc7b9cc067c03e00c9956dfce2b5870b96d790c99b8.into());
    all_constants.append(0x69ece46547140aa4a77cc801b21149161e57c9ac59e364621932d024146fd98.into());
    all_constants.append(0x04892ee7463dae425adc0a1c47d2b5eccff2c7fabdcffe1cf4ac05af245fca9.into());
    all_constants.append(0x0a25ae8c3b814f15f39084472ec38d2461778b92955e1d5611c7c1dbe7f462e.into());
    all_constants.append(0x2032b503ae5601d699448e626471ae9118cd8cb93002b1d28bf444e97c08334.into());
    all_constants.append(0x08a3312e15d4f5450488419f945648d1274324044e2e7836bc218c6c3284555.into());
    all_constants.append(0x1d283305a6027c5b6bf30e862d15835c3f78743261e8c054328f9d129057443.into());
    all_constants.append(0x7a529d6b06b3622e156a7c65c0e037590c33548aebdc3e9afd42416c6f486fb.into());
    all_constants.append(0x0cfb71f45fe3af619c9a8b96a9eb6d6d43c731ed145aa8476942fc68825692c.into());
    all_constants.append(0x647357e3d86d5563e043f608cfdbc4f11bfe701913a42ee0e41887014136708.into());
    all_constants.append(0x6c38f1ab17cc3a8dac576ee1c88c431be956a8adf69e7ef160f1c00c778c145.into());
    all_constants.append(0x5d20eee133c8731acacc2fed8217c16f3ca320a7fd67ebe96a20e0ea1ca896a.into());
    all_constants.append(0x14022cead9be0b928db8c2190bbd5e60e3b92bfdd3955a691bd5630e87eae68.into());
    all_constants.append(0x67ab6c2c6e3e25f6d80a693f3253a7d50fd0eeb974af292b5c1bf7df9366cee.into());
    all_constants.append(0x4bb6e4417f969fdcb00cce036b3230267e0335e574ab4ca01e1b65b03fc01c6.into());
    all_constants.append(0x79461d001789e5c70b2cc62beb9976d5f8f17a820ce7285d03e66d5dc6081d1.into());
    all_constants.append(0x2052461f7dfd7c3e52639f2112f4a2eb9ea01c52d227f1688425c18b38a6a50.into());
    all_constants.append(0x4e9f30b316d9c876a8c0e39027f7480909c4a93721f685fe803a86bd9cd49f5.into());
    all_constants.append(0x2185f0666b443897f0504c6aeb2c28d8215157645f11a9f7a923a3bd931d9e9.into());
    all_constants.append(0x068a833cddca44d75533a705128e003392093f8114d9d73a5b718f50de91ba0.into());
    all_constants.append(0x1108f8d5bd14320d8f66ccaa553ff41f1d0d3f4f169f76b3ab39b21c1b8f3ca.into());
    all_constants.append(0x2c8a1766e93e43a198264713606813c855737c96182c979d99d66a3815f5504.into());
    all_constants.append(0x6a7efb5f0151ee249d2451dea4120a8e9c3f16a3513b8eb9558b12c22e49769.into());
    all_constants.append(0x2647e3ffd4e54a6cc7abbfb0f2c1df58ea29ec907274080b4522fc0782ef368.into());
    all_constants.append(0x76818d1cb208ca51a4f5880618bf85bd09734c5585f2310edcd45e5a4f6fb9d.into());
    all_constants.append(0x2c5cabfb7875eff64fd4fad166c9d7ccc067244ae7ff4ca3d8a16faef9a4dab.into());
    all_constants.append(0x400b0b36c68828c090791f9d6d1cbb21fc938f6d4bab6ba4c86749efa870355.into());
    all_constants.append(0x1784e9d2a79ea4399cb60ba81489765f163ef6ab6b75ca2c870e43348bc310b.into());
    all_constants.append(0x0f9487028ded2afd617e24143be0fb1bb039281153c83407a7cd3ea54930164.into());
    all_constants.append(0x168f7cd569a2edbaa3d8ddd35733363eefe6075cc98e5ecd2a7eb2ff406a54d.into());
    all_constants.append(0x4ecaacb343345559b9e5af8750b99e76b30bb28d26803efd28ebe745984d181.into());
    all_constants.append(0x022ff9b9dbfcda7233a9544c6ec342ecc1d781c1880908eb150456b914a02f2.into());
    all_constants.append(0x02563049b87deacdbe499387ea166982b36127a5bbf8e113ae8d238d58df01b.into());
    all_constants.append(0x00f8e228cae158248722d67dbdbe6e3f69f14096c4f3dd59b4162e8907653a9.into());
    all_constants.append(0x393490b1615920ed3132b36be171ed945180ba10b059a7ce082f9eb9b1e418a.into());
    all_constants.append(0x0dd260da658e171d11bca0d8c6d5dd9e7565b975136ea23912ce6a2d3100502.into());
    all_constants.append(0x59d2bc34c9abbd3da728bf59ae9fdc974d7c34f05c81918a0d4d6ede252581a.into());
    all_constants.append(0x5cd79af2575006b645be4c7bbf03e157a08bc1ce778774a53b0517f6523d814.into());
    all_constants.append(0x261ac3afa6868161e30f25003eb9c1705b41f601463f71a702798cc6ba4488e.into());
    all_constants.append(0x2e08c1f1df12b884c0811eafd1dc1abbe65354bc25bd9e5656e6fe36d69b746.into());
    all_constants.append(0x1ee5066a3c74646ab6f64c4413dac8f35037f8c034e8aa8e9d8df4e15c541bd.into());
    all_constants.append(0x60c8c518e15873476ee202976191d8aca9393f9eab5bacb31cb277aebd63e36.into());
    all_constants.append(0x1ba582c064283539f72d99c8ea7a34ecd426a7464ff543ce9c6421efc434558.into());
    all_constants.append(0x75e99478a80fd87d0904f3a1bb532fe065dc5ab4b617b83a04ffb9c32c18274.into());
    all_constants.append(0x4b89d42e36e286fabbb3dd5a8fe7d1485d1b8cd72752ff2489e3165735564e2.into());
    all_constants.append(0x7183b545848b588371a6ca142d62df9514ee7a67f0682f22ac79e8441e3e914.into());
    all_constants.append(0x615bdcb2273475c9d0abe3ace37762a8af40da5e31fcefe6282b4e0a453cd32.into());
    all_constants.append(0x3f86a2144d7e0636f6794893026892d44bf2c4c52684e82ea23e1ed26fbcef9.into());
    all_constants.append(0x68f25e2fdebb838a66a2aaf1b72b1a2248d5a14f90da56c2d312daf569d6fcd.into());
    all_constants.append(0x172cba427350dd0f5e216c97b0389b1d14a13faf6b5deff3829d1026b78fb8a.into());
    all_constants.append(0x325f4c1a4429871822c8470d45dd877f0b01185c5141796042f8afb1399d58b.into());
    all_constants.append(0x65d6232c3d55cb30e111d5e0474512d3a919c399bb7714187f2694e5cd97b2d.into());
    all_constants.append(0x698d68254dc3247b1aff833a04d211b18e8d5da3ca9a26f8c964f22ea58b5ab.into());
    all_constants.append(0x09aa5d4121d22d4ffa2155a90651da7db7f83395e240bc69bb9acf1bf64ac9c.into());
    all_constants.append(0x2c281bd89f0507611fed3d79be9b8c07efa5afdf3f3c46ab5bccd998c507cd5.into());
    all_constants.append(0x6aa93f7d9c0f18c768f386b1c68108a1292cb9d59b4287de6842edb48f318cd.into());
    all_constants.append(0x69494be3bf696e20a987d2e906241abe49934bf0bc1afafb1209b2d1247b3c6.into());
    all_constants.append(0x766c3f448a306ff0722ffacaa15d0b6acc7838bc0a0815632fb92173c0e7fd4.into());
    all_constants.append(0x4a491c095712fb67694b2dc6808dd93788c7600c8155d8cebe911812d3bfbe9.into());
    all_constants.append(0x02eca60a8dce78a547f4bbf12735e519804563c6fda122c72be39840d67f0f5.into());
    all_constants.append(0x7f312cb5c8eca64419e5c5e0521fa86b0bc5c6b32ccec67683624b0e0fb6e30.into());
    all_constants.append(0x72d659723b105af4f4b5f16fc200f1707ecc842f9b113b36a75e2fd6e402be3.into());
    all_constants.append(0x617bb560606f0cb3b86c0fb929199d99b267583ccf6a774963cb54218ab0fe4.into());
    all_constants.append(0x7bcc4c9310f8eb931810c81419380337fe18c4c92b09dd2297812617695437d.into());
    all_constants.append(0x056865055e4e87b5dccf170cfb9f280cc391721224c6011b87cd64a4ee8d02c.into());

    loop {
        if all_constants.is_empty() {
            break;
        };

        let mut round_i_constants = ArrayTrait::new();

        round_i_constants.append(all_constants.pop_front().unwrap());
        round_i_constants.append(all_constants.pop_front().unwrap());
        round_i_constants.append(all_constants.pop_front().unwrap());

        round_constants.append(round_i_constants);
    };

    round_constants
}
