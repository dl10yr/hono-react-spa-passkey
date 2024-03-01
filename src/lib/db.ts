import { AuthenticatorDevice } from '@simplewebauthn/types'

type User = {
  username: string
  id: string
  authenticators: AuthenticatorDevice[]
  challenge?: string
}

class UserStore {
  private db: { [key: string]: User }

  constructor() {
    this.db = {
      'user00': { id: 'user00', username: 'user00', authenticators: [] },
      'user01': { id: 'user01', username: 'user01', authenticators: [] },
      'user02': { id: 'user02', username: 'user02', authenticators: [] },
    }
  }

  getUserById(id: string): User | undefined {
    return this.db[id]
  }

  setUser(user: User): void {
    this.db[user.id] = user
  }
}

export const userStore = new UserStore()
