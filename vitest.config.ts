import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    pool: 'forks',
    hookTimeout: 300_000
  }
})
