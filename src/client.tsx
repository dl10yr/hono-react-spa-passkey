import { createRoot } from 'react-dom/client'
import { useState } from 'react'

import { RegistrationResponseJSON } from '@simplewebauthn/types'

import { StartRegistrationResponse } from './routes/passkey'

import { Buffer } from 'buffer'
window.Buffer = Buffer

function App() {
  return (
    <>
      <h1>Register and Authenticate PassKey sample</h1>
      <RegisterAndAuthenticateByPassKey />
    </>
  )
}

function bufferToBase64URLString(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let str = '';

  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }

  const base64String = btoa(str);

  return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64URLStringToBuffer(base64URLString: string): ArrayBuffer {
  // Convert from Base64URL to Base64
  const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
  /**
   * Pad with '=' until it's a multiple of four
   * (4 - (85 % 4 = 1) = 3) % 4 = 3 padding
   * (4 - (86 % 4 = 2) = 2) % 4 = 2 padding
   * (4 - (87 % 4 = 3) = 1) % 4 = 1 padding
   * (4 - (88 % 4 = 0) = 4) % 4 = 0 padding
   */
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64.padEnd(base64.length + padLength, '=');

  // Convert to a binary string
  const binary = atob(padded);

  // Convert binary string to buffer
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return buffer;
}

const RegisterAndAuthenticateByPassKey = () => {
  const [response, setResponse] = useState<string | null>(null)

  const registerPassKey = async () => {

    const userId = 'user00'
    const startRegistrationResponse = await fetch('/api/passkey/start-registration', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        userId
      })
    })

    const startRegistrationResData = await startRegistrationResponse.json() as StartRegistrationResponse
    setResponse(JSON.stringify(startRegistrationResData, null, 2))

    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: base64URLStringToBuffer(startRegistrationResData.challenge),
        rp: {
          name: startRegistrationResData.rp.name
        },
        pubKeyCredParams: startRegistrationResData.pubKeyCredParams,
        user: {
          id: base64URLStringToBuffer(startRegistrationResData.user.id),
          name: startRegistrationResData.user.name,
          displayName: startRegistrationResData.user.displayName
        }
      }
    }) as PublicKeyCredential

    console.log(credential)

    if (!credential) { return }
    if (credential.type !== 'public-key') { return }

    const credentialResponse = credential.response as AuthenticatorAttestationResponse

    const registrationResponseJson: RegistrationResponseJSON = {
      rawId: bufferToBase64URLString(credential.rawId),
      response: {
        attestationObject: bufferToBase64URLString(credentialResponse.attestationObject),
        clientDataJSON: bufferToBase64URLString(credentialResponse.clientDataJSON)
      },
      id: credential.id,
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults()
    }

    const completeRegistrationResponse = await fetch('/api/passkey/complete-registration', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        userId,
        ...registrationResponseJson
      })
    })

    const completeRegistrationResponseData = await completeRegistrationResponse.json() as StartRegistrationResponse

    setResponse(JSON.stringify(completeRegistrationResponseData, null, 2))
  }

  const authenticatePassKey = async () => {
      
  }

  return (
    <div>
      {response && <pre>{response}</pre>}
      <button onClick={registerPassKey}>Register PassKey</button>
      <button onClick={authenticatePassKey}>Authenticate PassKey</button>
    </div>
  )
}

const domNode = document.getElementById('root')!
const root = createRoot(domNode)
root.render(<App />)