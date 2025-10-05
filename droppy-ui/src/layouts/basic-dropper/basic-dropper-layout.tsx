import React from 'react';
import { Header } from '@/layouts';
import { Container } from '@mui/material';


export default function BasicDropperLayout({ children }: BasicDropperLayoutProps) {
  return (
    <>
      <Header />
      <Container maxWidth="lg" sx={{ py: 10 }}>
        {children}
      </Container>
    </>
  );
};

interface BasicDropperLayoutProps {
  children: React.ReactNode;
}
