// AES-128 in CBC mode (aes-128-cbc) and CTR mode (aes-128-ctr)
// iv is chosen randomly

var _decrypt = function(algorithm, ciphertext, key) {
    var crypto = require('crypto'),
        encoding = 'hex',
        decipher, deciphered,
        keyBuffer, ctBuffer,
        iv, ivBuffer;

    console.log("Raw: " + ciphertext);

    // Extract the iv from the ciphertext
    iv = ciphertext.substr(0, 32);
    ciphertext = ciphertext.substr(32);

    // Create binary buffers
    ivBuffer  = new Buffer(iv, encoding);
    ctBuffer  = new Buffer(ciphertext, encoding);
    keyBuffer = new Buffer(key, encoding);

    console.log("CT : " + ciphertext);
    console.log("Key: " + key);
    console.log("IV : " + iv);
    console.log("CT length: " + ciphertext.length);

    decipher = crypto.createDecipheriv(algorithm, keyBuffer, ivBuffer);
    deciphered = decipher.update(ctBuffer, encoding);
    deciphered += decipher.final(encoding);

    console.log("PT:  " + deciphered);
    return (deciphered);
};

var cipherType, key, CT;

console.log("\nQuestion 1\n==========");
cipherType = "aes-128-cbc";
key = "140b41b22a29beb4061bda66b6747e14"; // 32 chars * 4 bits = 128 bits key
CT  = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
_decrypt(cipherType, CT, key);

console.log("\nQuestion 2\n==========");
cipherType = "aes-128-cbc";
key = "140b41b22a29beb4061bda66b6747e14"; // 128 bits key
CT  = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
_decrypt(cipherType, CT, key);

console.log("\nQuestion 3\n==========");
cipherType = "aes-128-ctr";
key = "36f18357be4dbd77f050515c73fcf9f2"; // 128 bits key
CT  = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
_decrypt(cipherType, CT, key);

console.log("\nQuestion 4\n==========");
cipherType = "aes-128-ctr";
key = "36f18357be4dbd77f050515c73fcf9f2"; // 128 bits key
CT  = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";
_decrypt(cipherType, CT, key);
