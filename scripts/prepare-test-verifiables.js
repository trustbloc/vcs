/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const axios = require('axios')
const fs = require('fs')

const bgGreen = "\x1b[32m"
const reset = "\x1b[0m"

const vcType = "VerifiableCredential"

// options based on various endpoints.
const opts = {
    providers: [
        {
            name: "transmute",
            types: ["UniversityDegreeCredential", "PermanentResidentCard"],
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
        },
        {
            name: "digitalbazaar",
            types: ["PermanentResidentCard"],
            vc: {
                path: "https://issuer.interop.digitalbazaar.com/credentials/issueCredential",
                request: `{
                "credential": %credential%
                    }`,
                replace: "%credential%"
            }
        },
        {
            name: "danubetech",
            types: ["UniversityDegreeCredential", "PermanentResidentCard"],
            vc: {
                path: "https://uniissuer.io/danubetech/credential-issuer/0.0.1/credentials/issueCredential",
                issuer: "did:v1:test:nym:z6Mkeac33uiSWFAfDM5wPUWDhGZFUWDvTji3zJ1yg4ADUpiW",
                request: `{
                "credential": %credential%
                    }`,
                replace: "%credential%",
                responseKey: "credential"
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
const createVerifiables = async (credentials) => {
    console.log(`Creating verifiable credentials and presentations from credential`)
    var responses = []

    for (const provider of opts.providers) {
        const response = {name: provider.name, output: []}
        let fileSuffix = 0

        for (let [type, credential] of credentials) {
            if (!provider.types.find(t => t == type)) {
                continue
            }

            fileSuffix++
            // create vc
            if (provider.vc) {
                console.log(`Creating verifiable credential of type ${type} for ${provider.name} submitting request to ${provider.vc.path}`)
                var credentialStr = JSON.stringify(credential)
                if (provider.vc.issuer) {
                    const cred = Object.assign({}, credential)
                    cred.issuer = provider.vc.issuer
                    credentialStr = JSON.stringify(cred)
                }

                const rqst = provider.vc.request.replace(provider.vc.replace, credentialStr)
                let resp
                try {
                    resp = await axios.post(provider.vc.path, rqst, axiosConfig)
                } catch (error) {
                    console.log(`Failed to create vc for ${provider.name}, cause ${error}`)
                    return
                }

                if (resp.status = 200) {
                    const output = `${process.env.OutputDir}${provider.name}_vc${fileSuffix}.json`
                    console.log(`Successfully created vc for ${provider.name}, writing to ${output}`)
                    const vcdata = (provider.vc.responseKey) ? JSON.parse(resp.data[provider.vc.responseKey]) : resp.data
                    writeToFile(output, vcdata)
                    response.output.push(output)
                    response.vc = vcdata
                } else {
                    console.log(`Failed to create VC for ${provider.name} : ${resp.data}`)
                    return
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
                    const output = `${process.env.OutputDir}${provider.name}_vp${fileSuffix}.json`
                    console.log(`Successfully created VP for ${provider.name}, writing to ${output}`)
                    writeToFile(output, resp.data)
                    response.output.push(output)
                } else {
                    console.log(`Failed to create VP for ${provider.name} : ${resp.data}`)
                    return
                }
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
        console.log(`Successfully created verifiables for ${response.name}, generated below files`,)
        response.output.forEach((file, index) => {
            console.log(bgGreen, `\t${file}`)
        })
        console.log("")
    })
    console.log(reset)
}

function getCredentialsMap(credentials) {
    const credsByType = new Map()
    credentials.forEach((credential) => {
            let c = require(`${process.env.InputDir}${credential}`)
            credsByType.set(getCredentialType(c), c)
        }
    )

    return credsByType
}

function getCredentialType(credential) {
    if (!credential.type || !Array.isArray(credential.type)) {
        throw "not a valid credential, invalid type. expected more than one type"
    }

    for (const t of credential.type) {
        if (t != vcType) {
            return t
        }
    }

    throw `unable to find type from credential ${credential}`
}

if (!process.env.OutputDir) {
    console.log("Please provide output directory")
    return
}

if (!process.env.InputDir) {
    console.log("Please provide input directory")
    return
}

if (!process.env.Credentials) {
    console.log("Please provide credentials")
    return
}

// group all credentials by type
const credentialsMap = getCredentialsMap(process.env.Credentials.split(","))

if (credentialsMap.size == 0) {
    console.log(`Unable to find valid ${process.env.Credentials} under ${process.env.InputDir}`)
    return
}

// create verifiable credentials and verifiable presentations.
createVerifiables(credentialsMap)

