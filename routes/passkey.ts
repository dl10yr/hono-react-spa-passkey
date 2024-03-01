import { Hono } from 'hono'

export const passkey = new Hono()

passkey.post('/start-registration', (c) => {
  return c.json({
    time: new Date().toLocaleTimeString()
  })
})

passkey.post('/complete-registration', (c) => {
  return c.json({
    time: new Date().toLocaleTimeString()
  })
})

passkey.get('/start-authenticate', (c) => {
  return c.json({
    time: new Date().toLocaleTimeString()
  })
})

passkey.post('/complete-registration', (c) => {
  return c.json({
    time: new Date().toLocaleTimeString()
  })
})

