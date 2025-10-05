import { Container, AppBar, Toolbar, Typography } from '@mui/material'
import { type ReactNode } from 'react'

export default function LoginLayout({ children }: { children: ReactNode }) {
  return (
    <>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6">Login</Typography>
        </Toolbar>
      </AppBar>
      <Container sx={{ mt: 4 }}>{children}</Container>
    </>
  )
}
