/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const {Sidetree} = require('@transmute/element-lib');
const axios = require('axios')
var Buffer = require('safe-buffer').Buffer
const bs58 = require('bs58')

const createElementDID = async () => {
    // Instantiate the Sidetree class
    const sidetree = new Sidetree({parameters: {didMethodName:"elem"}});

    // Create did element wallet
    const wallet = await sidetree.op.getNewWallet("elem")

    const pr = wallet.extractByTags([`#primary`])
    if (pr.length == 0) {
        console.log("unable to find primary key in wallet")
        return
    }
    const primaryKey = pr[0]

    // Generate a simple did document model
    const didDocumentModel = sidetree.op.walletToInitialDIDDoc(wallet)

    // Generate sidetree create payload
    const createPayload = await sidetree.op.getCreatePayload(didDocumentModel, primaryKey);
    console.debug(`sidetree request payload '${JSON.stringify(createPayload)}'`)

    // Print private keys ()
    const edKey = wallet.extractByTags([`Ed25519VerificationKey2018`])
    if (edKey.length == 0) {
        console.log("unable to find Ed25519VerificationKey2018 key in wallet")
        return
    }
    const privateKeyBs58 = bs58.encode(Buffer.from(primaryKey.privateKey, 'hex'))
    console.log(`base58 encoded secp256k1 primary private key ${privateKeyBs58}`)
    console.log(`Ed25519 private key for signing ${edKey[0].privateKey}`)

    // Submit payload to
    var resp
    try {
        const url = process.env.ElementAPIURL
        console.log(`posting payload sidetree request to ${url}`)
        resp = await axios.post(url, createPayload)
    } catch (error) {
        if (error.response.status == 502) {
            console.log("server temporary unavailable, please try again later")
        } else {
            console.log("failed to create sidetree request", error)
        }
        return
    }

    if (resp.status = 200) {
        console.log("successfully submitted payload")
        const didUniqueSuffix = sidetree.func.getDidUniqueSuffix(createPayload);
        const did = `did:elem:${didUniqueSuffix}`;

        console.log(`'${did}' was successfully created`);
    } else {
        console.log(`failed to create did, cause: ${resp.data}`)
    }

}

if (!process.env.ElementAPIURL) {
    console.log("Please provide element api endpoint for submitting sidetree request.")
    return
}

// create element DID
createElementDID()

