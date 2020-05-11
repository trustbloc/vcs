/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const axios = require('axios')
const fs = require('fs')

const bgGreen = "\x1b[32m"
const reset = "\x1b[0m"
const blue = '\033[34m'

const vcType = "VerifiableCredential"


// options based on various vendor endpoints.
const opts = {
    providers: [
        {
            name: "transmute",
            types: ["UniversityDegreeCredential", "PermanentResidentCard", "CrudeProductCredential", "CertifiedMillTestReport"],
            vc: {
                path: "https://vc.transmute.world/v0.1.0/issue/credentials",
            },
            vp: {
                path: "https://vc.transmute.world/v0.1.0/prove/presentations",
            }
        },
        {
            name: "digitalbazaar",
            types: ["PermanentResidentCard"],
            vc: {
                path: "https://issuer.interop.digitalbazaar.com/credentials/did%3Akey%3Az6MkkHSTSr9DSNLoioiVEZq8RKm9Sn1Xs4SjZXgzQASBMdc3/issueCredential",
            }
        },
        {
            name: "danubetech",
            types: ["PermanentResidentCard", "UniversityDegreeCredential"],
            vc: {
                path: "https://uniissuer.io/api/credentials/issueCredential",
                request: {
                    options: {
                        issuer: "did:v1:test:nym:z6MkfqxbQu6ikzpZRM3GwaFiUzy5vDgbmt99MGLA38kZUnEB",
                        assertionMethod: "did:v1:test:nym:z6MkfqxbQu6ikzpZRM3GwaFiUzy5vDgbmt99MGLA38kZUnEB#z6MkgmQGoevpPSeqb74jYSomuoWhXyJ9t5XtMAPq6NVFGssL"
                    }
                }
            }
        },
        {
            name: "mavennet",
            types: ["UniversityDegreeCredential", "PermanentResidentCard", "CrudeProductCredential", "CertifiedMillTestReport"],
            vc: {
                path: "https://api.neo-flow.com/credentials/issueCredential"
            },
            vp: {
                path: "https://api.neo-flow.com/credentials/presentation",
                request: {
                    options: {
                        issuer: "did:key:z6MkiTsvjrrPNDZ1rrg9QDEYCFWCmEswT6U2cEkScb7edQ9b",
                        proofPurpose: "authentication",
                        assertionMethod: "did:key:z6MkiTsvjrrPNDZ1rrg9QDEYCFWCmEswT6U2cEkScb7edQ9b#z6MkiTsvjrrPNDZ1rrg9QDEYCFWCmEswT6U2cEkScb7edQ9b"
                    }
                }
            }
        },
        {
            name: "factom",
            types: ["UniversityDegreeCredential", "PermanentResidentCard", "CrudeProductCredential", "CertifiedMillTestReport"],
            vc: {
                path: "https://vc.api.factom.sphereon.com/services/issue/credentials"
            }
        },
        {
            name: "sicpa",
            types: ["UniversityDegreeCredential", "PermanentResidentCard", "CrudeProductCredential"],
            vc: {
                path: "https://svip-interop.ocs-support.com/api/credentials/issueCredential",
                request: {
                    options: {
                        issuer: 'did:key:z6MkrqCMy45WhL3UEa1gGTHUtr17AvU4czfP5fH9KNDoYaYN',
                        assertionMethod: 'did:key:z6MkrqCMy45WhL3UEa1gGTHUtr17AvU4czfP5fH9KNDoYaYN#z6MkrqCMy45WhL3UEa1gGTHUtr17AvU4czfP5fH9KNDoYaYN',
                    }
                }
            }
        },
    ]
}

const axiosConfig = {
    headers: {
        'accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8',
    }
};

// ENABLE BELOW LINES FOR DEBUG
/*axios.interceptors.request.use(request => {
    console.log('Starting Request', request)
    return request
})

axios.interceptors.response.use(response => {
    console.log('Response:', response)
    return response
})*/

// createVerifiables creates verifiable credentials and veriable presentations.
const createVerifiables = async (credentials) => {
    console.log(`Creating verifiable credentials and presentations from credential`)
    var responses = []

    for (const provider of opts.providers) {
        console.log(blue, `\n Generating verifiables for provider ${provider.name}`, reset)
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
                const rqst = (provider.vc.request) ? provider.vc.request : {}
                rqst.credential = credential
                rqst.credential.id = vcID

                let resp
                try {
                    resp = await axios.post(provider.vc.path, rqst, axiosConfig)
                } catch (error) {
                    console.log(`Failed to create ${type} VC for ${provider.name}, cause ${error}`)
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
                    console.log(`Failed to create ${type} VC for ${provider.name} : ${resp.data}`)
                    return
                }
            }

            // create vp
            if (provider.vp) {
                console.log(`Creating verifiable presentation for ${provider.name}, submitting request to ${provider.vp.path}`)
                const rqst = (provider.vp.request) ? provider.vp.request : {}
                rqst.presentation = createPresentation(response.vc)

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
    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ],
        type: "VerifiablePresentation",
        verifiableCredential: vc
    }
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

function uuidv4() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

const vcID = `http://example.gov/credentials/${uuidv4()}`

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

