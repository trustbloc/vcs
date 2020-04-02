/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const axios = require('axios')

const bgGreen = "\x1b[32m"
const reset = "\x1b[0m"

// options based on did drivers.
const driverOpts = {
    "driver-did-v1": {
        path: "/1.0/register?driver-universalregistrar/driver-did-v1",
        options: {"options": {"ledger": "test", "keytype": "ed25519"}}
    },
    "driver-did-sov": {
        path: "/1.0/register?driver-universalregistrar/driver-did-sov",
        options: {"options":{"network":"danube"}},
        // send request to '' because of issue in local universal registrar
        // local universal registrar issue '"org.hyperledger.indy.sdk.ledger.TimeoutException: Timeout happens for ledger operation"'
        remote: true
    },
}

// createDIDFromRegistrar creates dids using given registrar url for given drivers.
const createDIDFromRegistrar = async (url, drivers) => {
    console.log(`Calling universal registrar '${url} for drivers '${drivers}'`)

    var responses = []
    for (const driver of drivers) {
        const opts = driverOpts[driver]
        if (!opts) {
            console.log(`Failed to create DID, unable to find options for driver '${driver}'`)
            return
        }

        var resp
        try {
            const registrarURL = (opts.remote) ? `${process.env.RegistrarRemoteURL}${opts.path}` : `${url}${opts.path}`
            console.debug(`Sending create did request for driver '${driver}' to endpoint '${registrarURL}'`)
            resp = await axios.post(registrarURL, opts.options)
        } catch (error) {
            console.log(`Failed to create DID for driver ${driver}, cause ${error}`)
            return
        }

        if (resp.status = 200) {
            const didState = resp.data["didState"]
            if (didState.state != "finished") {
                console.log(`Failed to create did for driver ${driver}, invalid state: ${didState.state}`)
                return
            }
            responses.push({id: didState.identifier, driver: driver, privateKeyBase58: didState.secret.keys[0].privateKeyBase58})
        } else {
            console.log(`Failed to create did for driver ${driver}, cause: ${resp.data}`)
            return
        }
    }

    responses.forEach(async function (response, index) {
        console.log(bgGreen, `\n driver: ${response.driver}`)
        console.log(bgGreen, `did: ${response.id}`)
        console.log(bgGreen, `privateKeyBase58: ${response.privateKeyBase58}\n`)
    });
    console.log(reset, `Number of dids created : ${responses.length}`)
}


if (!process.env.RegistrarLocalURL) {
    console.log("Please provide registrar endpoint for submitting requests.")
    return
}


if (!process.env.DRIVERS) {
    console.log("Please provide valid did drivers")
    return
}

const drivers = process.env.DRIVERS.split(",")

// create DIDs by calling universal registrar for given drivers
createDIDFromRegistrar(process.env.RegistrarLocalURL, drivers)

