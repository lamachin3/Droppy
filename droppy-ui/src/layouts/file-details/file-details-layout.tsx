import React from 'react';
import { Header } from '@/layouts';
import { Container } from '@mui/material';


export default function FileDetailsLayout({ children }: FileDetailsLayoutProps) {
  return (
    <>
      <Header />
      <Container maxWidth="lg" sx={{ py: 10 }}>
        {children}
      </Container>
    </>
  );
};

interface FileDetailsLayoutProps {
  children: React.ReactNode;
}
