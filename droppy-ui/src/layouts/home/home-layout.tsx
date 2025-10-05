import { Container } from '@mui/material'
import { Header } from '@/layouts'

export default function HomeLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <Header />
      <Container maxWidth="xl" sx={{ py: 10 }}>
        {children}
      </Container>
    </>
  )
}
