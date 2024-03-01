import { Hono } from 'hono'
import { userStore } from '../lib/db'
import { GenerateAuthenticationOptionsOpts, VerifiedAuthenticationResponse, VerifyAuthenticationResponseOpts, VerifyRegistrationResponseOpts, generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server'
import { RP_ID, RP_NAME } from '../lib/const'
import { isoBase64URL, isoUint8Array } from '@simplewebauthn/server/helpers'
import { AuthenticatorDevice } from '@simplewebauthn/types'

export const passkey = new Hono()

passkey.post('/start-registration', async (c) => {
  const body = await c.req.json()
  const userId = body['userId'] // 本来は、userIdはBearerトークンから取得するのが普通？

  if (!userId) {
    c.status(400)
    return c.json({error: 'userId is required'})
  }

  const user = userStore.getUserById(userId)

  if (!user) {
    c.status(404)
    return c.json({error: 'user not found'})
  }

  const credentialCreationOptions = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: user.id,
    userName: user.username,
    attestationType: 'direct',
    excludeCredentials: user.authenticators.map(authenticator => ({
      id: authenticator.credentialID,
      type: 'public-key',
      transports: authenticator.transports,
    })),
    authenticatorSelection: {
      residentKey: 'discouraged',
      userVerification: 'discouraged',
      authenticatorAttachment: 'cross-platform',
    },
  })

  return c.json({
    message: 'registration start is ok',
    ...credentialCreationOptions,
  })
})

passkey.post('/complete-registration', async (c) => {
  const body = await c.req.json()
  const userId = body['userId']

  const user = userStore.getUserById(userId)
  const expectedChallenge = user?.challenge

  if (!user || !expectedChallenge) {
    c.status(404)
    return c.json({error: 'user not found'})
  }

  const opts: VerifyRegistrationResponseOpts = {
    response: body,
    expectedChallenge: expectedChallenge,
    expectedOrigin: origin,
    expectedRPID: RP_ID,
    requireUserVerification: false,
  };

  let verification;

  try {
    verification = await verifyRegistrationResponse(opts)
  } catch (error) {
    c.status(400)
    return c.json({
      error: 'Can not validate response signature.',
    })
  }

  const { verified, registrationInfo } = verification

  if (!verified || !registrationInfo) {
    c.status(400)
    return c.json({
      error: 'Can not validate response signature.'
    })
  }

  const { credentialPublicKey, credentialID, counter } = registrationInfo;

  const existingAuthenticator = user.authenticators.find(authenticator =>
    isoUint8Array.areEqual(authenticator.credentialID, credentialID)
  )

  if (!existingAuthenticator) {
    const newDevice: AuthenticatorDevice = {
      credentialID,
      credentialPublicKey,
      counter,
      transports: body.response.transports,
    }
    userStore.setUser({
      ...user,
      authenticators: [...user.authenticators, newDevice]
    })
  }

  userStore.setUser({
    ...user,
    challenge: undefined
  })

  return c.json({
    message: 'registration complete is ok'
  })
})


passkey.get('/start-authenticate', async (c) => {
  const body = await c.req.json()
  const userId = body['userId']
  const user = userStore.getUserById(userId)

  if (!user) {
    c.status(404)
    return c.json({error: 'user not found'})
  }
  
  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: user.authenticators.map(authenticator => ({
      id: authenticator.credentialID,
      type: 'public-key',
      transports: authenticator.transports,
    })),
    userVerification: 'discouraged',
    rpID: RP_ID
  }
  const credentialGetOptions = await generateAuthenticationOptions(opts);

  userStore.setUser({
    ...user,
    challenge: credentialGetOptions.challenge
  })

  return c.json({
    message: 'authenticate start is ok',
    ...credentialGetOptions,
  })
})

passkey.post('/complete-registration', async (c) => {
  const body = await c.req.json()
  const userId = body['userId']
  const user = userStore.getUserById(userId)

  if (!user) {
    c.status(404)
    return c.json({error: 'user not found'})
  }
  
  const expectedChallenge = user.challenge

  let dbAuthenticator;
  const bodyCredIDBuffer = isoBase64URL.toBuffer(body.rawId)
  for (const authenticator of user.authenticators) {
    if (isoUint8Array.areEqual(authenticator.credentialID, bodyCredIDBuffer)) {
      dbAuthenticator = authenticator
      break
    }
  }

  if (!dbAuthenticator) {
    c.status(400)
    return c.json({error: 'authenticator is not registered'})
  }

  let verification: VerifiedAuthenticationResponse

  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: expectedChallenge ?? '',
      expectedOrigin: origin,
      expectedRPID: RP_ID,
      authenticator: dbAuthenticator,
      requireUserVerification: false
    }
  
    verification = await verifyAuthenticationResponse(opts)
  } catch (error) {
    c.status(400)
    return c.json({error: (error as Error).message})
  }

  const { verified, authenticationInfo } = verification
  
  if (!verified || !authenticationInfo) {
    c.status(400)
    return c.json({error: 'authenticate signature is failed'})
  }

  dbAuthenticator.counter = authenticationInfo.newCounter


  userStore.setUser({
    ...user,
    authenticators: [...user.authenticators, dbAuthenticator],
    challenge: undefined
  })

  return c.json({
    accessToken: 'accessTokenByPassKeyAuth'
  })

})
