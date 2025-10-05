// src/theme/theme-provider.tsx
import { ThemeProvider, CssBaseline } from '@mui/material'
import { type ReactNode } from 'react'
import { appTheme } from './app-theme'

const theme = appTheme()

export default function AppThemeProvider({ children }: { children: ReactNode }) {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {children}
    </ThemeProvider>
  )
}
