// Copyright(c) 2021 SkyeKiwi
// This code is licensed under MIT license (see LICENSE.txt for details)


import Keyring from '@polkadot/keyring';
import { waitReady } from '@polkadot/wasm-crypto'
import crypto from 'eth-crypto'
import secrets, { share } from 'secrets.js-grempe'

const main = async () => {

    // "some secret" will be shared with others
    var key = secrets.str2hex("some secret")
    
    // we divide the secret into 4 pieces and 2 of them can decrypt the message
    var shares = secrets.share(key, 4, 2)

    await waitReady()

    // generate two private/public key pair
    const acct1 = crypto.createIdentity()
    const acct2 = crypto.createIdentity()

    const keys1 = {
        privateKey: acct1.privateKey,
        publicKey: acct1.publicKey
    }

    const keys2 = {
        privateKey: acct2.privateKey,
        publicKey: acct2.publicKey
    }

    // generate two sr25519 substrate keypairs
    const keyring = new Keyring({
        type: "sr25519",
        ss58Format: 42
    })
    const pair1 = keyring.addFromUri(keys1.privateKey)
    const pair2 = keyring.addFromUri(keys2.privateKey)

    console.log("Addresses:");
    console.log(pair1.toJson())
    console.log(pair2.toJson())
    // Addresses:
    // {
        // address: '5DAs3MrRoppppF3uhDwqvQtWXEgNQQjtwkTkZN2aMv1w2iZu',
        // encoded: 'MFMCAQEwBQYDK2VwBCIEIFBtd1lSDBBdkW6mveDvkSE/InD2GxnpmmofqXhKrYBq/Okkq682
        // 0ngWiM6eiZcN13CJ1Y2Bra+fCYUeZ8aDcBOhIwMhADDun4SEJY2CtdFC24zRvc+gH6f9BEL4AIfW0TEjQZEO
        // ',
        // encoding: { content: [ 'pkcs8', 'sr25519' ], type: [ 'none' ], version: '3' },
        // meta: {}
    // }

    // {
        // address: '5HWWZEk53KakCRWz9PiFZxUTvCYdPRboNQyPWQKg1hNSb3dJ',
        // encoded: 'MFMCAQEwBQYDK2VwBCIEIDgj8SYIQYmkVOmaGJ1IQ0KvmrQSjgv78Exu+cf8ZGdomuGIgnnS
        // ZWsSKFxSZLaSUyS0Gw2iT4iipwlX8MSOyqmhIwMhAPDbgbzlUu6fHp1U9vveXXaC1eRr7qHU10+x314dv6pO
        // ',
        // encoding: { content: [ 'pkcs8', 'sr25519' ], type: [ 'none' ], version: '3' },
        // meta: {}
    // }


    console.log("Shares:");
    console.log(shares)
    // Shares:
    // [
    //     '8015859aa2630b4da708fcd5898132be1b40304eaf3aca13f511f1271bfbc1a338c',
    //     '802b0b2494c6075a9e00384b0b126f9dfe306adc95445ca7ec23e8be2d465856690',
    //     '803e8ebe36a50c173908c48e85d35b73e2505ca23c2e91841b321fc9306d9f0556f',
    //     '8047d799298c0ea4fdd06167de34c40a34d0ce28f078a1cfcf97ca4d902caa6cca8'
    // ]    

    // the share that will be shared without encryption 
    const public_share = shares[0]

    // encrypted1 will be shared with account1, encrypted 2 will be shared with account2
    const encrypted1 = await crypto.encryptWithPublicKey(keys1.publicKey, shares[1])
    const encrypted2 = await crypto.encryptWithPublicKey(keys2.publicKey, shares[2])

    console.log("Encrypted Msg:");
    console.log(crypto.cipher.stringify(encrypted1))
    console.log(crypto.cipher.stringify(encrypted2))

    // Encrypted Msg:
    // 35c3d741a3869114a69bde049ed198f503ffa5664ed2a46cab822a7617d930f52c53975701586e954763
    // 3f9438def29da7ac9505d189d1e68c2f30be6524d946070c705a7c6387fb14d15c2222b94859ebc0ca3b
    // 9dace5cb180099dbd1992cbddcff2850f650ffc9e4eb0f1929564457151beeaccdcc53a2d96bd3302054
    // f82774bfbd2276340599686d616f04a892c1ac3458c13fc17868ac928c34e986bd7682

    // c2628aacb971881666af8aa5489d358803f936060d0d1c202e48686f410e88df9f129f32d3372ae98ea2
    // bcbb45bf02722da0ccfd24550ba81f8587feea046ad4249b834ff02ae98c873f0b042b1acb6c7c67d99c
    // 5639b0a4815f74ecf886e1577d432fa6e7bf47d839af9d116c4d41a3a4ba936db5d038bda96a4925e0a7
    // af6b3f2c4d064b1a39e42294e366591e3d95d95afc6e69e759f96622f085f8df2cbca7

    ////////////////////////////////////////
    // behaviors on client side
    ////////////////////////////////////////

    const encrypted_obj1 = crypto.cipher.parse(encrypted1)
    const encrypted_obj2 = crypto.cipher.parse(encrypted2)

    const decrypted_msg1 = await crypto.decryptWithPrivateKey(keys1.privateKey, encrypted_obj1)
    const decrypted_msg2 = await crypto.decryptWithPrivateKey(keys2.privateKey, encrypted_obj2)

    console.log("Decrypted Msg:");
    console.log(decrypted_msg1);
    console.log(decrypted_msg2);

    // Decrypted Msg:
    // 802b0b2494c6075a9e00384b0b126f9dfe306adc95445ca7ec23e8be2d465856690
    // 803e8ebe36a50c173908c48e85d35b73e2505ca23c2e91841b321fc9306d9f0556f

    // combined the decrypted msg
    console.log("Combined:");

    // with only the public share, the msg is not decryptable
    console.log(secrets.hex2str(secrets.combine([public_share])))
    // ㎌밚熿ἒ㽑겡̄ጫ墘迍�ゴꨦᡙ


    // with any two of shares, the msg is decryptable
    console.log(secrets.hex2str(secrets.combine([public_share, decrypted_msg1])))
    // some secret

    console.log(secrets.hex2str(secrets.combine([public_share, decrypted_msg2])))
    // some secret

    console.log(secrets.hex2str(secrets.combine([decrypted_msg1, decrypted_msg2])))
    // some secret

}

main().catch(console.error)
// 0xe27128659e969339C33D40d50dE840f8A0BAE5FB
// a19acf9f18cf5dd28c86bfdf4f4a4588637bb743d5e2dfbb53fb8feae428934382ff28a5019112ed466f4f52fb51373bef7fd4eb49a6046b2287f988dd91145c
// 0x3d6d3b15d6b9bb661e9fb0668ca180c09b79700da37bb10a1755c03211ad4398
