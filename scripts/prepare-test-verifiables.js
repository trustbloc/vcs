/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const axios = require('axios')
const fs = require('fs')

const bgGreen = "\x1b[32m"
const reset = "\x1b[0m"

// options based on various endpoints.
const opts = {
    providers: [
        {
            name: "transmute",
            vc: {
                path: "https://vc.transmute.world/credentials/issueCredential",
                request: `{
                "credential": %credential%
                    }`,
                replace: "%credential%"
            },
            vp: {
                path: "https://vc.transmute.world/vc-data-model/presentations",
                request: `{
                  "presentation": %presentation% 
                }`,
                replace: "%presentation%"
            }
        }
    ]
}

const presentationTemplate = {
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
    ],
    type: "VerifiablePresentation",
    verifiableCredential: {}
}

const axiosConfig = {
    headers: {
        'accept': 'application/json',
        'Content-Type': 'application/json',
    }
};

// createVerifiables creates verifiable credentials and veriable presentations.
const createVerifiables = async (credential) => {
    console.log(`Creating verifiable credentials and presentations from credential`)

    var responses = []
    const credentialStr = JSON.stringify(credential)
    for (const provider of opts.providers) {
        const response = {name: provider.name, output: []}
        // create vc
        if (provider.vc) {
            console.log(`Creating verifiable credential for ${provider.name}, submitting request to ${provider.vc.path}`)

            const rqst = provider.vc.request.replace(provider.vc.replace, credentialStr)
            let resp
            try {
                resp = await axios.post(provider.vc.path, rqst, axiosConfig)
            } catch (error) {
                console.log(`Failed to create vc for ${provider.name}, cause ${error}`)
                return
            }

            if (resp.status = 200) {
                const output = `${process.env.OutputDir}${provider.name}_vc.json`
                console.log(`Successfully created vc for ${provider.name}, writing to ${output}`)
                writeToFile(output, resp.data)
                response.output.push(output)
                response.vc = resp.data
            } else {
                console.log(`Failed to create VC for ${provider.name} : ${resp.data}`)
                continue
            }
        }

        // create vp
        if (provider.vp) {
            console.log(`Creating verifiable presentation for ${provider.name}, submitting request to ${provider.vp.path}`)
            const rqst = provider.vp.request.replace(provider.vp.replace, JSON.stringify(createPresentation(response.vc)))

            let resp
            try {
                resp = await axios.post(provider.vp.path, rqst, axiosConfig)
            } catch (error) {
                console.log(`Failed to create VP for ${provider.name}, cause ${error}`, resp)
                return
            }

            if (resp.status = 200) {
                const output = `${process.env.OutputDir}${provider.name}_vp.json`
                console.log(`Successfully created VP for ${provider.name}, writing to ${output}`)
                writeToFile(output, resp.data)
                response.output.push(output)
            } else {
                console.log(`Failed to create VP for ${provider.name} : ${resp.data}`)
                continue
            }
        }

        responses.push(response)
    }

    printResponseMessage(responses)
}

async function writeToFile(file, data) {
    const content = JSON.stringify(data, null, '\t')
    fs.writeFile(file, content, err => {
        if (err) {
            console.log('Error writing file :', err)
        }
    })
}

function createPresentation(vc) {
    const p = Object.assign({}, presentationTemplate)
    p.verifiableCredential = vc
    return p
}

function printResponseMessage(responses) {
    console.log(bgGreen)
    responses.forEach((response, index) => {
        console.log(`Successfully created verifiables for ${response.name}`)
        console.log("Generated below files: ")
        response.output.forEach((file, index) => {
            console.log(bgGreen, `\t${file}`)
        })
    })
    console.log(reset)
}

if (!process.env.OutputDir) {
    console.log("Please provide output directory")
    return
}

if (!process.env.CredentialPath) {
    console.log("Please provide input credential")
    return
}

const credential = require(`${process.env.CredentialPath}`)

// create verifiable credentials and verifiable presentations.
createVerifiables(credential)

